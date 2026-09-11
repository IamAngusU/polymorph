from __future__ import annotations
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("render_evidence",ROOT/"scripts/render_evidence.py")
assert spec and spec.loader
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)


def stage(tmp):
    for name in ('README.md','README.de.md'):
        shutil.copyfile(ROOT/name,tmp/name)
    shutil.copytree(ROOT/'knowledge',tmp/'knowledge')
    return tmp


def test_renderer_regenerates_both_languages_and_badges(tmp_path):
    root=stage(tmp_path)
    assert len(r.render(root)) >= 3
    assert r.render(root,check=True)==[]
    for name in ('README.md','README.de.md'):
        text=(root/name).read_text()
        assert '353.52' in text and '52.41' in text
        assert '365' in text and '1,656' in text
        assert 'lab candidate' in text
        assert text.count('| Date / evidence |' if name == 'README.md' else '| Datum / Nachweis |')==1


def test_stale_badge_is_caught(tmp_path):
    root=stage(tmp_path);r.render(root)
    (root/'docs/assets/training.svg').write_text('stale')
    assert 'docs/assets/training.svg' in r.render(root,check=True)


def test_negative_or_bool_training_counters_are_rejected(tmp_path):
    root=stage(tmp_path)
    p=root/'knowledge/evidence/lab-0.2-demo.json'
    data=json.loads(p.read_text());data['evidence']['unique_train_queries']=True
    p.write_text(json.dumps(data))
    with pytest.raises(ValueError):r.render(root)


def test_multiple_devices_stay_in_one_table(tmp_path):
    root=stage(tmp_path)
    p=root/'knowledge/benchmarks/20260910-legacy.json';d=json.loads(p.read_text())
    for n in range(3):
        d['hardware']['cpu_model']=f'TEST CPU {n}'
        (root/f'knowledge/benchmarks/test-{n}.json').write_text(json.dumps(d))
    r.render(root)
    text=(root/'README.md').read_text()
    assert text.count('| Date / evidence |')==1
    assert all(f'TEST CPU {n}' in text for n in range(3))


def test_unsafe_package_path_rejected(tmp_path):
    root=stage(tmp_path)
    (root/'knowledge/latest.json').write_text(json.dumps({'package':'../secrets'}))
    with pytest.raises(ValueError):r.render(root)


def test_device_text_is_not_markdown_or_html():
    value=r.clean('<img src=x>|[link](x)`')
    assert '<img' not in value and '|' not in value and '[' not in value and '`' not in value
