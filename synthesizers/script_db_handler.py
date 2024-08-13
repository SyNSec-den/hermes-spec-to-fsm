"""
This is the public release of the code of our paper titled
"Hermes: Unlocking Security Analysis of Cellular Network Protocols by Synthesizing Finite State Machines from Natural
    Language Specifications" (USENIX Security '24)
Author: Abdullah Al Ishtiaq
Contact: abdullah.ishtiaq@psu.edu

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import time

import sqlite3
from sqlite3 import OperationalError, IntegrityError, DataError

import script_config

INF = 9999
KEYWORD_DB_TABLE = script_config.keyword_db_table
min_keyword_dist_cache = {}

CONN_CLOSED = True


def get_new_conn_cursor():
    global CONN_CLOSED
    db_conn = sqlite3.connect("hermes.sqlite")
    db_cursor = db_conn.cursor()

    try:
        db_cursor.execute("CREATE TABLE {} (Substring TEXT NOT NULL, MatchedString TEXT NOT NULL, "
                          "Keyword TEXT NOT NULL, Distance INTEGER NOT NULL, MatchedStringLen INTEGER NOT NULL, "
                          "PRIMARY KEY (Substring, MatchedString));".format(KEYWORD_DB_TABLE))
    except OperationalError:
        pass

    CONN_CLOSED = False
    return db_conn, db_cursor


def db_commit(db_conn):
    db_conn.commit()


def close_connection(db_conn, db_cursor):
    global CONN_CLOSED
    if not CONN_CLOSED:
        db_cursor.close()
        db_conn.close()
        CONN_CLOSED = True


def check_conn_closed():
    return CONN_CLOSED


def update_substring_keyword_distance(db_conn, db_cursor, substring: str, matched_string: str, keyword: str,
                                      distance: int):
    if len(substring) > 180 or len(matched_string) > 180 or len(keyword) > 180:
        print("Length too long for :", substring, matched_string, keyword, distance)
        return

    sql = "UPDATE {} SET keyword = ?, Distance = ?  WHERE Substring = ? AND MatchedString = ?".format(KEYWORD_DB_TABLE)
    val = (keyword, distance, substring, matched_string)
    try:
        db_cursor.execute(sql, val)
    except OperationalError:
        print("Sleeping for a bit...")
        time.sleep(5.0)
        update_substring_keyword_distance(db_conn, db_cursor, substring, matched_string, keyword, distance)


def insert_substring_keyword_distance(db_conn, db_cursor, substring: str, matched_string: str, keyword: str,
                                      distance: int, force_update=False, thread_num=0):
    if len(substring) > 180 or len(matched_string) > 180 or len(keyword) > 180:
        print("Length too long for :", substring, matched_string, keyword, distance)
        return

    sql = "INSERT INTO {} (Substring, MatchedString, Keyword, Distance, MatchedStringLen) " \
          "VALUES (?, ?, ?, ?, ?)".format(KEYWORD_DB_TABLE)
    val = (substring, matched_string, keyword, distance, len(matched_string))

    try:
        db_cursor.execute(sql, val)
    except IntegrityError:
        if force_update:
            update_substring_keyword_distance(db_conn, db_cursor, substring, matched_string, keyword, distance)
    except DataError:
        print("DataError for :", val)
        return
    except OperationalError:
        print("Thread {}: Sleeping for a bit...".format(thread_num))
        time.sleep(5.0)
        print("Thread {}: Resuming...".format(thread_num))
        insert_substring_keyword_distance(db_conn, db_cursor, substring, matched_string, keyword, distance,
                                          force_update, thread_num=thread_num)


def insert_substring_keyword_distance_batch(db_conn, db_cursor, insert_list, force_update=False, thread_num=0):
    for item in insert_list:
        insert_substring_keyword_distance(db_conn, db_cursor, item[0], item[1], item[2], item[3],
                                          force_update, thread_num=thread_num)
    db_commit(db_conn)


def lookup_substring_keyword_distance(db_cursor, substring: str, matched_string: str) -> (str, int):
    sql = "SELECT Keyword, Distance FROM {} WHERE Substring = ? AND MatchedString = ?".format(KEYWORD_DB_TABLE)
    val = (substring, matched_string)
    db_cursor.execute(sql, val)
    db_result = db_cursor.fetchall()

    if len(db_result) > 0:
        return db_result[0][0], db_result[0][1]
    else:
        return "", INF


def get_min_keyword_distance(db_cursor, substring: str) -> (str, str, int):
    if substring in min_keyword_dist_cache:
        return min_keyword_dist_cache[substring]

    sql = "select * from {} " \
          "where Substring = ? " \
          "and Distance = (select min(Distance) from {} where Substring = ?) " \
          "order by MatchedStringLen DESC " \
          "limit 1".format(KEYWORD_DB_TABLE, KEYWORD_DB_TABLE)
    val = (substring, substring)
    db_cursor.execute(sql, val)
    db_result = db_cursor.fetchall()

    if len(db_result) > 0:
        result = (db_result[0][1], db_result[0][2], db_result[0][3])
    else:
        result = ("", "", INF)

    min_keyword_dist_cache[substring] = result
    return result


def substring_in_db(db_cursor, substring: str) -> bool:
    sql = "select * from {} " \
          "where Substring = ? " \
          "limit 1".format(KEYWORD_DB_TABLE)
    val = (substring,)
    db_cursor.execute(sql, val)
    db_result = db_cursor.fetchall()
    return len(db_result) > 0


def matched_string_in_db(db_cursor, matched_string: str) -> bool:
    sql = "select * from {} " \
          "where MatchedString = ? " \
          "limit 1".format(KEYWORD_DB_TABLE)
    val = (matched_string,)
    db_cursor.execute(sql, val)
    db_result = db_cursor.fetchall()
    return len(db_result) > 0


def delete_matched_string(db_conn, db_cursor, matched_string: str):
    sql = "delete from {} " \
          "where MatchedString = ?".format(KEYWORD_DB_TABLE)
    val = (matched_string,)
    try:
        db_cursor.execute(sql, val)
    except OperationalError:
        print("Sleeping for a bit...")
        time.sleep(5.0)
        delete_matched_string(db_conn, db_cursor, matched_string)
