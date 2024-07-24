


def split_dn(dn):
    # 'CN=11c,OU=11c,OU=Students,OU=default-school,OU=SCHOOLS...' becomes :
    # [['CN', '11c'], ['OU', '11c'], ['OU', 'Students'],...]
    return [node.split("=") for node in dn.split(',')]

def get_common_name(dn):
    try:
        # [['CN', '11c'], ['OU', '11c'], ['OU', 'Students'],...]
        return split_dn(dn)[0][1]
    except KeyError:
        return ''