def eq_obj_slots(l, r):
    """
    Compares objects with __slots__ defined
    """
    for f in l.__slots__:
        if getattr(l, f, None) != getattr(r, f, None):
            return False
    return True


def eq_obj_contents(l, r):
    """
    Compares object contents, supports slots
    """
    if l.__class__ is not r.__class__:
        return False
    if hasattr(l, "__slots__"):
        return eq_obj_slots(l, r)
    else:
        return l.__dict__ == r.__dict__


def slot_obj_dict(o):
    """
    Builds dict for o with __slots__ defined
    """
    d = {}
    for f in o.__slots__:
        d[f] = getattr(o, f, None)
    return d


def is_type(x, types, full=False):
    """
    Returns true if x is of type in types tuple
    """
    types = types if isinstance(types, tuple) else (types,)
    ins = isinstance(x, types)
    sub = False
    try:
        sub = issubclass(x, types)
    except Exception:
        pass
    res = ins or sub
    return res if not full else (res, ins)


def get_ftype_params(field):
    return field[1], field[2:]
