# build_gui.py — 编译图形界面版本（BlockAV GUI）
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))

VC = r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207"
KIT = r"C:\Program Files (x86)\Windows Kits\10"
KITV = "10.0.26100.0"

CL = os.path.join(VC, r"bin\Hostx64\x64\cl.exe")
if not os.path.exists(CL):
    print("[ERROR] cl.exe not found:", CL)
    sys.exit(1)

env = os.environ.copy()
env["PATH"] = os.path.join(VC, r"bin\Hostx64\x64") + ";" + \
             os.path.join(KIT, r"bin", KITV, "x64") + ";" + env.get("PATH", "")
env["INCLUDE"] = ";".join([
    os.path.join(VC, "include"),
    os.path.join(KIT, "Include", KITV, "ucrt"),
    os.path.join(KIT, "Include", KITV, "um"),
    os.path.join(KIT, "Include", KITV, "shared"),
])
env["LIB"] = ";".join([
    os.path.join(VC, "lib", "x64"),
    os.path.join(KIT, "Lib", KITV, "ucrt", "x64"),
    os.path.join(KIT, "Lib", KITV, "um", "x64"),
])

src = os.path.join(ROOT, "src", "gui.cpp")
out = os.path.join(ROOT, "ErBaiAV.exe")

cmd = [
    CL, "/nologo", "/std:c++17", "/O2", "/EHsc", "/W3", "/utf-8",
    "/D_CRT_SECURE_NO_WARNINGS",
    src,
    "/Fe:" + out,
    "/link", "/SUBSYSTEM:WINDOWS",
    "user32.lib", "gdi32.lib", "comctl32.lib", "comdlg32.lib", "shell32.lib", "ole32.lib",
    "advapi32.lib",
]

print("[BUILD GUI]", " ".join(cmd))
r = subprocess.run(cmd, env=env, cwd=ROOT)
if r.returncode != 0:
    print("[ERROR] GUI build failed (code %d)" % r.returncode)
    sys.exit(r.returncode)
print("[DONE] generated", out)
