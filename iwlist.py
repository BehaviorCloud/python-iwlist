import re
import subprocess

cellNumberRe = re.compile(
    r"^Cell\s+(?P<cellnumber>.+)\s+-\s+Address:\s(?P<mac>.+)$")
regexps = [
    re.compile(r"^ESSID:\"(?P<essid>.*)\"$"),
    re.compile(r"^Protocol:(?P<protocol>.+)$"),
    re.compile(r"^Mode:(?P<mode>.+)$"),
    re.compile(
        r"^Frequency:(?P<frequency>[\d.]+) (?P<frequency_units>.+) \(Channel (?P<channel>\d+)\)$"),
    re.compile(r"^Encryption key:(?P<encryption>.+)$"),
    re.compile(
        r"^Quality=(?P<signal_quality>\d+)/(?P<signal_total>\d+)\s+Signal level=(?P<signal_level_dBm>.+) d.+$"),
    re.compile(r"^Signal level=(?P<signal_quality>\d+)/(?P<signal_total>\d+).*$"),
]

# Detect encryption type
wpaRe = re.compile(r"IE:\ WPA\ Version\ 1$")
wpa2Re = re.compile(r"IE:\ IEEE\ 802\.11i/WPA2\ Version\ 1$")
enterpriseRe = re.compile(r"802\.1x")


def scan(interface='wlan0'):
    """Runs the comnmand to scan the list of networks.

    Must run as super user.
    Does not specify a particular device, so will scan all network devices.

    interface : str, optional
        The network interface to use (the default is 'wlan0', which is the
                default network interface in major OSs)

    Returns
    -------
    str
        The response from launched command "iwlist scan"
    """
    cmd = ["iwlist", interface, "scan"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    points = proc.stdout.read().decode('utf-8')
    return points


def parse(content):
    """Parses the response from the command "iwlist scan"

    Parameters
    ----------
    content : str
        Scan result from `scan` method
    Returns
    -------
    dict
        Dictionary with all wifi cells with their attributes
    """
    cells = []
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        cellNumber = cellNumberRe.search(line)
        if cellNumber:
            cells.append(cellNumber.groupdict())
            continue
        wpa = wpaRe.search(line)
        if wpa:
            cells[-1].update({'encryption': 'wpa'})
        wpa2 = wpa2Re.search(line)
        if wpa2:
            cells[-1].update({'encryption': 'wpa2'})
        enterprise = enterpriseRe.search(line)
        if enterprise:
            current_encryption = ''
            if cells and 'encryption' in cells[-1]:
                current_encryption = cells[-1].get('encryption')
            cells[-1].update({'encryption': current_encryption +
                              '-e'})
        for expression in regexps:
            result = expression.search(line)
            if result:
                if 'encryption' in result.groupdict():
                    if result.groupdict()['encryption'] == 'on':
                        cells[-1].update({'encryption': 'wep'})
                    else:
                        cells[-1].update({'encryption': 'off'})
                else:
                    cells[-1].update(result.groupdict())
                continue
    return cells
