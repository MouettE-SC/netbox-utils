def move_devices(nb, id_rack, pos1, pos2, offset):

    if pos1 > pos2:
        pos1, pos2 = pos2, pos1

    if offset > 0:
        start = pos2-1
        end = pos1-2
        step = -1
    elif offset < 0:
        start = pos1-1
        end = pos2
        step = 1
    else:
        return False, ["Invalid offset"]

    m = []
    try:
        r = nb.dcim.racks.get(id=id_rack)

        rt = [None for _ in range(r.u_height)]

        devices = nb.dcim.devices.filter(rack_id=r.id)
        for d in devices:
            if not d.position:
                continue
            rt[int(d.position)-1] = d

        for i in range(start, end, step):
            if rt[i] is None:
                continue
            if offset > 0:
                rt[i].position += 1.0
                rt[i].save()
                m.append("Moved {} up {} rows".format(rt[i].name, offset))
            else:
                rt[i].position -= 1.0
                rt[i].save()
                m.append("Moved {} down {} rows".format(rt[i].name, -offset))
        return True, m
    except Exception as e:
        m.append(str(e))
        return False, m
