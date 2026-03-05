import xml.etree.ElementTree as ET


def parse_dmarc_report(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    results = []

    for record in root.findall(".//record"):
        source_ip = record.findtext("row/source_ip")
        count = record.findtext("row/count")
        dkim = record.findtext("row/policy_evaluated/dkim")
        spf = record.findtext("row/policy_evaluated/spf")

        results.append({
            "source_ip": source_ip,
            "count": count,
            "dkim": dkim,
            "spf": spf
        })

    return results


if __name__ == "__main__":
    report = parse_dmarc_report("sample_dmarc.xml")

    for entry in report:
        print(entry)
