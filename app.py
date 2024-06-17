import random
import string
import pynetbox
from psycopg2.pool import ThreadedConnectionPool
from flask import Flask, render_template, request, session, redirect, url_for, send_file
import os.path, shutil
import zipfile
import tarfile
from hashers import verify_password
from subprocess import run
from rack import move_devices

app = Flask(__name__)
app.secret_key = 'd264440cfa13dd54d77264bb535e346c25a695309c3c37f7c5c6f2c6f31f3900'
netbox_config = '/opt/netbox/netbox/netbox/configuration.py'
netbox_installed = False
db_conn: ThreadedConnectionPool
db_conn = None
netbox_init = False
sessions = dict()

@app.before_request
def setup():
    global netbox_installed, db_conn, netbox_init, app
    app.before_request_funcs[None].remove(setup)
    if not os.path.exists(netbox_config):
        return
    netbox_installed = True
    exec(open(netbox_config).read(), globals())

    db_conn = ThreadedConnectionPool(2, 10, database=DATABASE['NAME'], user=DATABASE['USER'], password=DATABASE['PASSWORD'])
    try:
        db = db_conn.getconn()
        try:
            db.autocommit = True
            with db.cursor() as cursor:
                cursor.execute("select * from django_migrations limit 1")
        except:
            return
        finally:
            db_conn.putconn(db)
    except:
        app.logger.exception("Unable to connect to database")
        return
    netbox_init = True

@app.errorhandler(404)
def not_found(e):
    return "<p>Not found</p>"

def check_app(need_db):
    global netbox_installed, db_conn, sessions
    if not netbox_installed:
        return False, None, "Netbox install not detected"
    if need_db:
        try:
            db = db_conn.getconn()
            db.autocommit = True
        except:
            return False, None, "No database connection"
    else:
        db = None
    if 'id' not in session:
        session['id'] = ''.join(random.choices(string.ascii_uppercase + string.digits, k=32))
    if session['id'] not in sessions:
        sessions[session['id']] = {'nb': None}
    return True, db, sessions[session['id']]


def rack_list(nb):
    res = dict()
    for r in nb.dcim.racks.all():
        res[r.id] = r.name
    return res

@app.route('/')
def index():
    valid, _, s_data = check_app(False)
    if not valid:
        return f"<p>{s_data}</p>"
    if not netbox_init:
        return render_template('init.html')
    if not s_data['nb']:
        return render_template('login.html')
    try:
        rl = rack_list(s_data['nb'])
    except:
        return "<p>Unable to connect to netbox instance</p>"
    return render_template('index.html', racks=rl)


@app.route('/login', methods=['GET', 'POST'])
def login():
    global db_conn
    valid, db, s_data = check_app(True)
    try:
        if not valid:
            return f"<p>{s_data}</p>"
        if request.method == 'GET':
            return render_template('login.html')
        with db.cursor() as c:
            c.execute("select id,password,is_superuser from users_user where username = %s", (request.form['username'],))
            r = c.fetchone()
            if not r or not verify_password(request.form['password'], r[1]):
                return render_template('login.html', error="Invalid authentication information")
            if not r[2]:
                return render_template('login.html', error="User must be Netbox Superuser")
            c.execute("select key from users_token where user_id=%s and write_enabled=True", (r[0], ))
            r = c.fetchone()
            if not r:
                return render_template('login.html', error="No available token for this user")
            s_data['nb'] = pynetbox.api('http://localhost', token=r[0])
            return redirect(url_for('index'))
    finally:
        if db:
            db_conn.putconn(db)

@app.route('/move-rack', methods=['POST'])
def move_rack():
    valid, _, s_data = check_app(False)
    if not valid:
        return f"<p>{s_data}</p>"
    if not s_data['nb']:
        return render_template('login.html')
    r, m = move_devices(s_data['nb'], int(request.form['rack']), int(request.form['start']), int(request.form['end']), int(request.form['offset']))
    if r:
        return render_template('index.html', racks=rack_list(s_data['nb']), mr_messages=m)
    else:
        return render_template('index.html', racks=rack_list(s_data['nb']), mr_errors=m)


@app.route('/restore', methods=['POST'])
def restore():
    global db_conn
    valid, _, s_data = check_app(False)
    if not valid:
        return f"<p>{s_data}</p>"
    if 'restore' not in request.files:
        return f"<p>No file uploaded</p>"
    try:
        request.files['restore'].save('/tmp/netbox.zip')
        with zipfile.ZipFile('/tmp/netbox.zip', 'r') as z:
            z.extract('netbox.sql', '/tmp')
            z.extract('netbox.tar', '/tmp')
    except:
        app.logger.exception("Error reading restore file")
        return f"<p>Error reading restore file</p>"

    db_conn.closeall()

    rc = run(['sudo', '/usr/bin/systemctl', 'stop', 'netbox'])
    if rc.returncode != 0:
        return f"<p>Unable to stop netbox service :</p><pre>{rc.stderr.decode('utf8')}</pre>"

    rc = run(['sudo', '/usr/bin/systemctl', 'stop', 'netbox-rq'])
    if rc.returncode != 0:
        return f"<p>Unable to stop netbox-rq service :</p><pre>{rc.stderr.decode('utf8')}</pre>"

    pg_env = dict(os.environ)
    pg_env['PGDATABSE'] = 'postgres'
    pg_env['PGUSER'] = DATABASE['USER']
    pg_env['PGPASSWORD'] = DATABASE['PASSWORD']
    rc = run(['/usr/bin/psql', '-c', 'drop database netbox', '-c', 'create database netbox', '-c', '\\c netbox', '-f', '/tmp/netbox.sql'], capture_output=True, env=pg_env)
    if rc.returncode != 0:
        return f"<p>DB restore error :</p><pre>{rc.stderr.decode('utf8')}</pre>"

    try:
        for r in '/opt/netbox/netbox/media/devicetype-images', '/opt/netbox/netbox/media/image-attachments':
            for f in os.listdir(r):
                ff = os.path.join(r, f)
                if os.path.isdir(ff):
                    shutil.rmtree(ff)
                else:
                    os.unlink(ff)
        with tarfile.open('/tmp/netbox.tar', 'r') as t:
            t.extractall('/opt/netbox/netbox/media')
    except:
        app.logger.exception("Unable to restore media files")
        return f"<p>Unable to restore media files</p>"
    s_data['nb'] = None
    rc = run(['sudo', '/usr/bin/systemctl', 'start', 'netbox'])
    if rc.returncode != 0:
        return f"<p>Unable to start netbox service :</p><pre>{rc.stderr.decode('utf8')}</pre>"

    rc = run(['sudo', '/usr/bin/systemctl', 'start', 'netbox-rq'])
    if rc.returncode != 0:
        return f"<p>Unable to start netbox-rq service :</p><pre>{rc.stderr.decode('utf8')}</pre>"

    return render_template('login.html')

@app.route('/backup', methods=['GET'])
def backup():
    valid, _, s_data = check_app(False)
    if not valid:
        return f"<p>{s_data}</p>"
    if not s_data['nb']:
        return render_template('login.html')
    pg_env = dict(os.environ)
    pg_env['PGDATABSE'] = DATABASE['NAME']
    pg_env['PGUSER'] = DATABASE['USER']
    pg_env['PGPASSWORD'] = DATABASE['PASSWORD']
    rc = run(['/usr/bin/pg_dump', '-f', '/tmp/netbox.sql'], capture_output=True, env=pg_env)
    if rc.returncode != 0:
        return f"<p>DB backup error :</p><pre>{rc.stderr.decode('utf8')}</pre>"
    if os.path.exists('/tmp/netbox.tar'):
        os.unlink('/tmp/netbox.tar')
    rc = run(['/usr/bin/tar', 'cf', '/tmp/netbox.tar', '.'], capture_output=True, cwd='/opt/netbox/netbox/media')
    if rc.returncode != 0:
        return f"<p>media files backup error :</p><pre>{rc.stderr.decode('utf8')}</pre>"
    with zipfile.ZipFile(file='/tmp/netbox.zip', mode='w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.write('/tmp/netbox.tar', arcname='netbox.tar')
        z.write('/tmp/netbox.sql', arcname='netbox.sql')
    return send_file('/tmp/netbox.zip', as_attachment=True, download_name='netbox.zip')

if __name__ == '__main__':
    app.run()
