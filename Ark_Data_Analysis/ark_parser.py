class Response:
    ip = None
    rtt = 0.0
    nTries = 0

    def __init__(self, IP, RTT, NTries):
        self.ip = IP
        self.rtt = RTT
        self.nTries = NTries


def process_hop_record(hop):
    if hop == "q":
        return None

    responses = hop.split(";")
    if len(responses) > 1:
        pass
    ret = []
    for response in responses:
        data_items = response.split(",")
        hop_ip = data_items[0]
        rtt = float(data_items[1])
        nTries = int(data_items[2])
        ret.append(Response(IP=hop_ip, RTT=rtt, NTries=nTries))

    return ret


def process_route_record(tokens):
    src = tokens[1]
    dst = tokens[2]
    hops = tokens[13:]

    hops_parsed = [process_hop_record(hop) for hop in hops]
    ip_list = []
    delay_list = []
    for hop in hops_parsed:
        if hop is None:
            ip_list.append("*")
            delay_list.append('')
        else:
            first_response = hop[0]
            ip_list.append(first_response.ip)
            delay_list.append(' {} ms {} ms {} ms'.format(first_response.rtt, first_response.rtt, first_response.rtt))

    return src, dst, ip_list, delay_list


def read_from_warts(warts_file_path, limit=100):
    ret = []
    counter = 1
    with open(warts_file_path) as warts_file:
        for line in warts_file:
            if line.startswith('T\t'):
                tokens = line.strip().split("\t")
                src, dst, IP_route, path_delay = process_route_record(tokens)
                ret.append([src, dst, IP_route, path_delay])
                if counter < limit:
                    counter += 1
                else:
                    return ret

    return ret