"""Load seven accepted baseline modules from verified bytes, without import paths."""
import builtins
import hashlib
from pathlib import Path
import types

BASELINE = Path(__file__).resolve().parent.parent / 'I7-Autonomous-20261014T045957Z'
PINS = {
 'junit/junit_accounting.py': '2bf47661862178752eb43da9da3aa9d6d4d712a0e4c38981c2778e02eff3c835',
 'mechanical/process_receipts.py': 'b754f0ca23f23332961600148736bce66372a0b7e3782b241efc2289bcb0abe1',
 'mechanical/synthetic_probe.py': 'f20226d81cae9793189cd6a7731eed7c8d090d32d5a7de6a17d488c375048684',
 'binding/operational_bindings.py': '7dca812b5ed23a84b4b003d36e4dd05cb3a3632b5be18f2fd23448f3d59dcfd3',
 'accounting_manifest.py': '83920750b366b7b3eb0b559dc97ae3a6f01a06bb825bbb21a7e5fcc0ac3b1f1e',
 'security/receipt_registry.py': '10f43eb17e9b3df94d666125268709661a7a8a3b4653057f64150019b7c18724',
 'synthetic_pipeline.py': 'c55a7064b4ddb44fc9b06279517a56cb0a9ae6fd9be39f51dd05cb02e324b2ab'}
MODULES = {}
SOURCE_READS = []

def _import(name, globals=None, locals=None, fromlist=(), level=0):
    resolved = globals['__package__'] + '.' + name if level else name
    if resolved in MODULES:
        return MODULES[resolved]
    if resolved.split('.')[0] in ('junit', 'mechanical', 'binding', 'security', 'accounting_manifest', 'synthetic_pipeline'):
        raise ImportError('unverified baseline dependency: ' + resolved)
    return builtins.__import__(name, globals, locals, fromlist, level)

for relative, digest in PINS.items():
    path = BASELINE / relative
    body = path.read_bytes()
    SOURCE_READS.append({'path': str(path), 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()})
    if SOURCE_READS[-1]['sha256'] != digest:
        raise ValueError('accepted baseline source hash mismatch: ' + relative)
    name = relative[:-3].replace('/', '.')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = name.rpartition('.')[0]
    module.__dict__['__builtins__'] = dict(vars(builtins), __import__=_import)
    exec(compile(body, str(path), 'exec'), module.__dict__)
    MODULES[name] = module

def source_pins():
    return dict(PINS)
