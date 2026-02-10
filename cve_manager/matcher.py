def normalize(s):
    return s.lower().replace("_", " ").replace("-", " ")

def match_programs_to_cves(programs, cves):
    matches = []

    for cve in cves:
        cpe = (cve["cpe"] or "").lower()

        for prog in programs:
            if normalize(prog) in normalize(cpe):
                matches.append(cve)
                break

    return matches
