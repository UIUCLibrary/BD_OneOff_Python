import csv
import functools
import itertools
import os
import sys
import typing
import collections

####################
SAMPLE_FILE = "ContentFiles/2017_01_17_30112121779331_dirList.csv"
FILE_ENCODING = "UTF16"
# FILE_ENCODING = "UTF8"
OUTPUT_REPORT = "duplicates.csv"
TSV_PATH = ""

####################

sorted_set = collections.namedtuple("sorted_set", ("key", "records"))


class ComparisonTable(collections.defaultdict):
    def __init__(self, source, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.source = source

    pass


class Record(collections.UserDict):
    def __init__(self, source, line_num, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.line_num = line_num
        self.source = source

    def __hash__(self) -> int:
        return hash((self.source, self.line_num))


class Report(collections.UserList):
    def __init__(self, keys, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.keys = keys


def get_data(file, encoding):
    with open(file, "r", encoding=encoding) as f:
        # ==========================
        # For csv
        # reader = csv.DictReader(f)
        # ==========================
        # For TSV
        reader = csv.DictReader(f, delimiter="\t")
        # ==========================

        for d in reader:
            yield Record(file, reader.line_num, d)


def sort_my_data(data):
    sorted_by_extension = sorted(data, key=lambda x: os.path.splitext(x["Filename"])[1])
    grouped_by_extension = itertools.groupby(sorted_by_extension, key=lambda x: os.path.splitext(x["Filename"])[1])
    files_interested = dict()

    for ext, group in grouped_by_extension:
        if not ext or len(ext) > 8:
            continue
        group = list(group)
        files_interested[ext] = group

    return files_interested


def save_report(filename, records):
    fields = records[0].keys()
    with open(filename, "w") as w:
        csv_writer = csv.DictWriter(w, fields)
        csv_writer.writeheader()
        for record in records:
            csv_writer.writerow(record)


def reduce_filesize(a, b):
    try:
        size = int((b["Size (bytes)"]))
    except ValueError:
        print("Record wasn't able to get the size for value \"{}\"".format(b["Size (bytes)"]),
              file=sys.stderr)
        size = 0
    return a + size


def create_report_data(files_interested):
    for extension, files in files_interested.items():
        report_record = {
            "File Extension": extension,
            "total": len(files),
            "Storage Total": functools.reduce(reduce_filesize, files, 0),

        }
        yield report_record


def get_tsv_files(path):
    for root, dirs, files in os.walk(path):
        for _file in files:
            if os.path.splitext(_file)[1] == ".csv":
                yield os.path.join(root, _file)


def create_comparison_table(source, data, key):
    new_table = ComparisonTable(source, list)
    for record in data:
        new_table[record[key]].append(record)
    return new_table


def write_dup_report(dups, filename):
    with open(filename, "w") as fp:
        writer = csv.DictWriter(fp, fieldnames=dups.keys)
        writer.writeheader()
        writer.writerows(dups)


def create_dups_report(records, keys):
    def my_sorter(value):
        if value["Size (bytes)"]:
            return value["Filename"], value["Size (bytes)"]
        else:
            return value["Filename"], ""

    dup_report = Report(keys=keys + ["Source csv file", "Source csv line number"])
    data = list()
    for record in add_records(keys, records):
        data.append(record)

    for x in sorted(data, key=my_sorter):
        dup_report.append(x)
    return dup_report


def add_records(keys, records):
    for k, unsorted_records in records.items():
        sorted_records = sorted(unsorted_records, key=lambda r: (r.source, r.line_num))
        for record in sorted_records:

            # include the source of the record and the line number
            report = {
                "Source csv file": record.source,
                "Source csv line number": record.line_num,

            }

            # Copy over all requested data from the record into the report
            for key in keys:
                report[key] = record[key]
            yield report


def main():
    tsv_files = get_tsv_files(path=TSV_PATH)

    print("Looking for duplicate files")
    dups = find_dups(tsv_files)

    print("Prepping report")
    report = create_dups_report(dups, keys=["Filename", "Full Path", "Size (bytes)"])

    print("Writing report")
    write_dup_report(report, filename=OUTPUT_REPORT)
    print("Report saved to {}".format(os.path.abspath(OUTPUT_REPORT)))


def find_dups(tsv_files):
    comparison_tables = []

    dups = collections.defaultdict(set)
    for i, tsv_file in enumerate(tsv_files):

        # ======================
        # # TODO: REMOVE THIS LINE
        # if i > 9:
        #     break
        # ======================
        try:
            print("Loading records from {}".format(tsv_file))
            data = get_data(file=tsv_file, encoding=FILE_ENCODING)
            # data = list(get_data(file=tsv_file, encoding=FILE_ENCODING))

            # Create a comparison table with size as the key
            new_comparison_table = create_comparison_table(tsv_file, data, key="Size (bytes)")

            # for every existing table check for existing
            if comparison_tables:
                print("Comparing {} to {} files".format(os.path.basename(tsv_file), len(comparison_tables)))

                for filename, matches in find_matching_files(new_comparison_table, comparison_tables):
                    for match in matches:
                        dups[filename].add(match)

            comparison_tables.append(new_comparison_table)

        except csv.Error as e:
            print("Error reading {}. Reason: {}".format(tsv_file, e))
            continue
        except UnicodeError as e:
            print("Error decoding {}. Reason: {}".format(tsv_file, e))
    return dups


def find_matching_files(new_table, comparison_tables):
    def sortby_int(value: str):
        try:
            return int(value)
        except ValueError:
            return hash(value)
        except TypeError:
            return hash(value)

    def find_matching_by_file_name(records) -> typing.List[Record]:
        def my_sorter(value):
            if value["Full Path"]:
                return value["Full Path"]
            else:
                return hash(None)

        s_records = sorted(records, key=lambda r: r["Filename"])
        for filename, group in itertools.groupby(s_records, key=lambda r: r["Filename"]):
            results = list(group)
            if len(results) > 1:
                yield sorted(results, key=my_sorter)
                # print(filename, len(results))

    def group_by_size(first, compare_to_table) -> typing.List[sorted_set]:
        for file_size in sorted(first.keys(), key=sortby_int):
            if file_size not in compare_to_table:
                continue
            # if the file_size already exists, that means there is another file with this exact fil esize

            set_from_new_data = first[file_size]
            set_from_exisiting_data = compare_to_table[file_size]

            combined = sorted(itertools.chain(set_from_exisiting_data, set_from_new_data), key=lambda x: x["Filename"])

            yield sorted_set(file_size, combined)

    dups = set()

    for indexed_table in comparison_tables:
        for size_result in group_by_size(new_table, indexed_table):
            for match in find_matching_by_file_name(size_result.records):
                for d in match:
                    dups.add(d)

    sdup = sorted(dups, key=lambda r: r["Filename"])
    for filename, group in itertools.groupby(sdup, key=lambda r: r["Filename"]):
        yield filename, list(group)


if __name__ == '__main__':
    main()
