import subprocess

def get_installed_programs():
    programs = []
    try:
        result = subprocess.run(
            'wmic product get Name, Version',
            shell=True,
            capture_output=True,
            text=True
        )
        lines = result.stdout.splitlines()
        for line in lines[1:]:  # Başlık satırını atla
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 1:
                continue
            # Name ve Version birleştirilip kaydediliyor
            name = " ".join(parts[:-1])
            version = parts[-1]
            programs.append(f"{name} {version}")
    except Exception as e:
        print("Program listesi alınamadı:", e)
    return programs
