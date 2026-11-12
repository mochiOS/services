from pathlib import Path
import subprocess, shutil, hashlib, json
import argparse
parser = argparse.ArgumentParser(description="Stage signed executable-reference fixtures in a private VM rootfs")
parser.add_argument('--stage', type=Path, required=True)
parser.add_argument('--sdk', type=Path, required=True)
parser.add_argument('--native-directory', type=Path, required=True)
parser.add_argument('--msign', type=Path, required=True)
args = parser.parse_args()
stage = args.stage.resolve()
sdk = args.sdk.resolve()
msign = args.msign.resolve()
native = args.native_directory.resolve()
bundle = stage/'system/applications/ExecRefTest.app'
bundle.mkdir(parents=True, exist_ok=True)
probe = native/'executable-reference-probe'
shutil.copyfile(probe,bundle/'entry.elf');(bundle/'entry.elf').chmod(0o755)
(stage/'system/bin').mkdir(parents=True,exist_ok=True)
source = Path(__file__).with_name('worker.c')
for name,message in [('worker','owned-helper\\n'),('external','external-helper\\n'),('forbidden','forbidden-helper\\n')]:
    target=stage/'system/bin'/('exe-'+name)
    args=['x86_64-elf-gcc','--sysroot='+str(sdk/'sysroot'),'-isystem',str(sdk/'sysroot/include'),'-D__mochios__','-O2','-static','-nostdlib','-nostartfiles','-Wl,-T,'+str(sdk/'lib/linker.ld'),'-Wl,-z,noexecstack','-DMESSAGE="'+message+'"',str(source),'-o',str(target),'-Wl,--start-group',str(sdk/'lib/crt0.o'),str(sdk/'lib/libmochi_user_newlib_runtime.a'),'-L'+str(sdk/'sysroot/lib'),'-lc','-lm','-lgcc','-Wl,--end-group']
    subprocess.run(args,check=True);target.chmod(0o755)

def file_record(fid,logical,physical):
    return f'\n[[file]]\nid={json.dumps(fid)}\npath={json.dumps(logical)}\ndigest="sha256:{hashlib.sha256(physical.read_bytes()).hexdigest()}"\nsize={physical.stat().st_size}\nmode="0755"\n'

caps=['process.spawn','ipc.client','ipc.server','fs.write.tmp','fs.read.tmp','system.random.read','system.time.read']
text='''format=1
[package]
provenance="built-in"
id="org.mochios.dev.exec-ref"
name="ExecRefTest"
version="1"
kind="application"
architecture="x86_64"
abi="mochios-1"
[application]
entry="entry.elf"
resources=[]
'''
text+=file_record('parent','/system/applications/ExecRefTest.app/entry.elf',bundle/'entry.elf')
text+='\n[[binary]]\npath="/system/applications/ExecRefTest.app/entry.elf"\nfile="parent"\nkind="application"\nrequires='+json.dumps(caps)+'\nexecutable_exports=["worker","forbidden"]\nexecutable_dependencies=["external-worker","bad-abi"]\n'
for name in ['worker','forbidden']:
    path='/system/bin/exe-'+name
    text+=file_record(name,path,stage/'system/bin'/('exe-'+name))
    text+='\n[[binary]]\npath='+json.dumps(path)+'\nfile='+json.dumps(name)+'\nkind="application"\nrequires='+json.dumps(['ipc.client','ipc.server']+(['fs.write.all'] if name=='forbidden' else []))+'\n'
    text+='\n[[executable_export]]\nname='+json.dumps(name)+'\nbinary='+json.dumps(path)+'\n'
for alias,abi in [('external-worker','mochios-1'),('bad-abi','wrong-abi')]:
    text+='\n[[executable_dependency]]\nalias='+json.dumps(alias)+'\npackage="org.mochios.dev.external-helper"\ndeveloper="org.mochios.system"\nsubject_key_id="'+('0'*64)+'"\nprovenance="built-in"\nabi='+json.dumps(abi)+'\nexport="worker"\n'
external='''format=1
[package]
provenance="built-in"
id="org.mochios.dev.external-helper"
name="ExternalHelper"
version="1"
kind="library"
architecture="x86_64"
abi="mochios-1"
'''+file_record('worker','/system/bin/exe-external',stage/'system/bin/exe-external')+'''\n[[binary]]
path="/system/bin/exe-external"
file="worker"
kind="application"
requires=["ipc.client","ipc.server"]
[[executable_export]]
name="worker"
binary="/system/bin/exe-external"
'''
launcher_bundle=stage/'system/applications/PortSmoke.app'
launcher_bundle.mkdir(parents=True,exist_ok=True)
shutil.copyfile(native/'executable-reference-launcher',launcher_bundle/'entry.elf')
(launcher_bundle/'entry.elf').chmod(0o755)
launcher='''format=1
[package]
provenance="built-in"
id="org.mochios.dev.exec-launcher"
name="PortSmoke"
version="1"
kind="application"
architecture="x86_64"
abi="mochios-1"
[application]
entry="entry.elf"
resources=[]
[[binary]]
path="/system/applications/PortSmoke.app/entry.elf"
kind="application"
requires=["process.spawn","fs.read.all","ipc.client","ipc.server","system.random.read","system.time.read"]
'''
for name,source_text in [('exec-ref',text),('external-helper',external),('port-smoke',launcher)]:
    package=stage/'system/packages'/name
    package.mkdir(parents=True,exist_ok=True)
    manifest=package/'fixture-input.toml'
    manifest.write_text(source_text,encoding='utf-8')
    subprocess.run([str(msign),'package','bind-built-in',str(manifest),'--rootfs',str(stage),'--output',str(package/'manifest.toml')],check=True)
    subprocess.run([str(msign),'package','built-in-record',str(package/'manifest.toml'),'--output',str(package/'verification.bin')],check=True)
    manifest.unlink()
print('Fixture stage ready:',stage)
