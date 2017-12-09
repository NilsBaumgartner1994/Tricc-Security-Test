
def readRoute(filename="gps_burger_king_route.txt"):
    """
    Reads gps coordinates from files, except for first and last line. Format in file, e.g.[52.286851666666664, 8.033383333333333, 501552],
    :param filename: String with the filename
    :return: [[lat, long], [lat, long], .... ] with lat and long as floats
    """
    with open(filename) as file:
        lines = file.readlines()
        values = []
        for i in range(1, len(lines) -1) :
            next= lines[i].split("[")[1]
            lat = next.split(",")[0]
            long = next.split(",")[1]
            time = next.split(",")[2].split("]")[0]

            values.append([float(lat), float(long), int(time)])

    return values


if __name__ == "__main__":
   readRoute()



