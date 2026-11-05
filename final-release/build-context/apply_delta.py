"""Apply reviewed final-state delta in one offline layer; no package installation."""
from pathlib import Path,PurePosixPath
import os,tarfile,json,hashlib,shutil,stat
B=Path('/mnt');meta=json.loads((B/'metadata.json').read_text())
def path(name):
 p=PurePosixPath(name);assert not p.is_absolute() and '..' not in p.parts and str(p) not in {'.',''}
 q=Path('/')/str(p)
 assert not q.is_relative_to(B)
 for parent in q.parents:
  assert not parent.is_symlink(),str(parent)
 return q

def remove(q):
 if q.is_symlink() or q.is_file():q.unlink()
 elif q.is_dir():q.rmdir() # Children are explicitly enumerated before parents; never recursive.
 elif q.exists():raise ValueError('unexpected special removal')

def attrs(q,row):
 os.chown(q,row['uid'],row['gid'],follow_symlinks=False)
 if not q.is_symlink():os.chmod(q,row['mode'])
 else:assert row['mode']==0o777
 os.utime(q,(row['mtime'],row['mtime']),follow_symlinks=False)
 for key,val in row['pax'].items():
  if key.startswith('SCHILY.xattr.'):os.setxattr(q,key[len('SCHILY.xattr.'):],val.encode(),follow_symlinks=False)
  else:assert key in {'path','linkpath','mtime'},key

for name in sorted(set(meta['deletions']+meta['type_replacements']),key=lambda s:-len(PurePosixPath(s).parts)):
 remove(path(name))
with tarfile.open(B/'delta.tar','r:') as a:
 members={m.name:m for m in a};assert set(members)==set(meta['changed'])
 for name,row in sorted(meta['changed'].items(),key=lambda t:len(PurePosixPath(t[0]).parts)):
  if row['type']=='dir':path(name).mkdir(exist_ok=True)
 for name,row in meta['changed'].items():
  if row['type'] in {'dir','hardlink'}:continue
  q=path(name);m=members[name];assert q.parent.is_dir()
  if row['type']=='symlink':
   if q.exists() or q.is_symlink():remove(q)
   assert m.issym() and m.linkname==row['linkname'];q.symlink_to(row['linkname'])
  elif row['type']=='file':
   assert m.isreg()
   if q.is_symlink() or q.is_file():q.unlink()
   h=hashlib.sha256();n=0
   with a.extractfile(m) as src,q.open('xb') as out:
    for b in iter(lambda:src.read(1024**2),b''):out.write(b);h.update(b);n+=len(b)
   assert h.hexdigest()==row['sha256'] and n==row['size']
  else:raise ValueError('unsupported changed type')
  attrs(q,row)
 for name,row in meta['changed'].items():
  if row['type']!='hardlink':continue
  q=path(name);target=path(row['linkname']);assert target.is_file() and not target.is_symlink()
  if q.exists() or q.is_symlink():remove(q)
  os.link(target,q);attrs(q,row)
for name,row in sorted(meta['old_directories'].items(),key=lambda t:-len(PurePosixPath(t[0]).parts)):
 attrs(path(name),row)
print(json.dumps({'applied_entries':len(meta['changed']),'removed_entries':len(meta['deletions']),'network_or_installs':0}))
