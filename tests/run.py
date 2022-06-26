#!/usr/bin/env python3

from pathlib import Path
from subprocess import call
from tempfile import mkdtemp
from typing import Any, Dict

import json
import os
import re
import sys


def clone_git_repo(repo: str, target: str) -> bool:
    if os.path.exists(target):
        print(repo, 'seems to be already cloned')
        return False

    print(target, 'is not cloned yet', flush=True)

    ret = call(f'git clone --depth 1 {repo} {target}', shell=True)
    if ret != 0:
        print('Cloning failed with return code', ret)
        sys.exit(1)

    print(target, 'cloned successfully')
    return True


def modify_repo(test: Dict[str, Any]):
    for rm in test['remove']:
        for file in Path(test['name']).glob(rm):
            print('Removing', file)
            os.unlink(file)

    for replace in test['fixup']:
        for glb in replace['files']:
            for file in Path(test['name']).glob(glb):
                regex = re.compile(replace['regex'], re.MULTILINE)
                regex_str = replace['regex'].replace('\n', '\\n')
                print('Removing lines matching', regex_str, 'from', file)
                with open(file, 'r') as f:
                    lines = f.read()
                with open(file, 'w') as f:
                    f.write(regex.sub('', lines))


def execute_test(test: Dict[str, Any]):
    name = test['name']
    print('Running test', name)

    if clone_git_repo(test['repo'], test['name']):
        modify_repo(test)

    jar = Path('../build/libs/javacard-profiler-1.0-SNAPSHOT.jar')
    jckit = Path(f'jcsdk/jc{test["jckit"]}_kit')

    cmd = f'java -jar {jar} -i "{Path(test["name"]) / test["path"]}" ' + \
          f'--jckit "{jckit}" --simulator --repeat-count 1000'

    if 'entryPoint' in test:
        cmd += f' --entry-point "{test["entryPoint"]}"'
    if 'resetInst' in test:
        cmd += f' --reset-inst "{test["resetInst"]}"'
    if 'cla' in test:
        cmd += f' --cla "{test["cla"]}"'

    for subtest in test['subtests']:
        sub_cmd = cmd
        test_dir = mkdtemp(prefix=f'{test["name"]}_{subtest["method"]}_')
        print('Created temporary directory', test_dir)

        sub_cmd += f' --output-dir "{test_dir}"'
        sub_cmd += f' --method "{subtest["method"]}"'
        sub_cmd += f' --inst "{subtest["inst"]}"'
        sub_cmd += f' --input-regex "{subtest["input"]}"'

        print('Executing subtest', subtest['method'])
        print('Command:', sub_cmd, flush=True)

        ret = call(sub_cmd, shell=True)
        if ret != 0:
            print('Command failed with return code', ret)
            sys.exit(1)

    # TODO: check format and contents of generated profiling reports


def main():
    root = Path(__file__).parent.resolve()
    print('Test root:', root)
    os.chdir(root)

    with open('test_data.json') as f:
        data = json.load(f)

    clone_git_repo(data['jcsdkRepo'], 'jcsdk')
    for t in data['tests']:
        execute_test(t)


if __name__ == '__main__':
    main()
