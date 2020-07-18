"""
This module contains useful operations, not strictly related to cybersecurity contexts.
"""

from datetime import datetime


def append_if_absent(data, size, file):
    """Appends data at the end of file if it is not already present in it.
    If the file doesn't exist, a new one is created.
    :param data: the bytes sequence to append to the file
    :param size: the length of data
    :param file: the file to write the data in
    """
    try:
        with open(file, "rb") as f:
            content = f.read()
    except FileNotFoundError:
        with open(file, "wb+") as f:
            f.write(data)
        return

    with open(file, "ab") as f:
        c = split_in_chunks(content, size)
        if data not in c:
            f.write(data)


def split_sequence(a, n):
    """Splits a in n sections.
    :param a: an iterable
    :param n: the number of sections a will be divided
    :raises ValueError if len(a) is not a multiple of n
    :return sections: a list of n partitions of a"""
    if not len(a) % n == 0:
        raise ValueError(f'{len(a)} is not a multiple of {n}')

    length_of_a = len(a)

    sections = [a[i: i + length_of_a // n] for i in range(0, length_of_a, length_of_a // n)]

    return sections


def split_in_chunks(a, n):
    """Splits a in sections of n elements.
    :param a: an iterable
    :param n: the number of elements for each section a will be divide in
    :returns a list of partitions of a of length n"""
    return split_sequence(a, len(a) // n)


def get_current_minutes():
    """Returns how many minutes have passed since today@00:00.
    For example, if the current datetime is 00:07, 7 will be returned.
    If the current datetime is 02:34, 154 will be returned.
    :return minutes: the number of minutes passed since today@00:00 """
    now = datetime.now()
    today = datetime(now.year, now.month, now.day, 0, 0, 0, 0)
    diff = now - today
    seconds = diff.seconds
    minutes = seconds // 60
    return minutes
