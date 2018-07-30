import difflib
import json
import re
from os import listdir, path


class TestUtilities:

    @staticmethod
    def get_next_test(directory: str):
        for file in listdir(directory):
            file_path = path.join(directory, file)
            yield TestUtilities._extract(file_path)

    @staticmethod
    def _extract(file: str):
        with open(file, 'r') as f:
            current_test_case = json.loads(f.read())
        return current_test_case

    @staticmethod
    def find_failures(answer: str, expected: str):
        d = difflib.Differ()
        expected_tag = ""
        expected_value = ""

        tag_faults_added = list()
        tag_faults_missing = list()
        value_faults_added = list()
        value_faults_missing = list()

        match = re.search(r'^\(([0-9]*).*(\[.*\])\)$', answer.replace("b'", "h'"))
        answer_tag = match.group(1)
        answer_value = match.group(2)

        match = re.search(r'^([0-9]*).*$', expected.lower())
        if match:
            expected_tag = match.group(1)
        match = re.search(r'(\[.*\])', expected.lower())
        if match:
            expected_value = match.group(1)

        print(answer_value)
        print(expected_value)

        diff = d.compare(answer_tag, expected_tag)

        for e in diff:
            if e.startswith("+"):
                tag_faults_added.append(e[-1:])
            if e.startswith("-"):
                tag_faults_missing.append(e[-1:])

        diff = d.compare(answer_value, expected_value)

        for e in diff:
            if e.startswith("+"):
                value_faults_added.append(e[-1:])
            if e.startswith("-"):
                value_faults_missing.append(e[-1:])

        print ("".join(tag_faults_added), "".join(tag_faults_missing), "".join(value_faults_added),
                "".join(value_faults_missing))


if __name__ == "__main__":
    print(next(TestUtilities.get_next_test("../testcases/mac0-tests")))

    str1 = "zuefzepfibuz"
    str2 = "zuefaazepfibuz"

    print(TestUtilities.find_failures(str1, str2))
