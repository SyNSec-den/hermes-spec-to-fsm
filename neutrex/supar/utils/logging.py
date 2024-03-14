# -*- coding: utf-8 -*-
"""
This is the public release of the code of our paper titled
"Hermes: Unlocking Security Analysis of Cellular Network Protocols by Synthesizing Finite State Machines from Natural
    Language Specifications" (USENIX Security '24)
Author: Abdullah Al Ishtiaq and Sarkar Snigdha Sarathi Das
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

import logging
import os

from supar.utils.parallel import is_master
from tqdm import tqdm


def get_logger(name):
    return logging.getLogger(name)


class TqdmHandler(logging.StreamHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def emit(self, record):
        try:
            msg = self.format(record)
            tqdm.write(msg)
            self.flush()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handleError(record)


def init_logger(logger,
                path=None,
                mode='w',
                level=None,
                handlers=None,
                verbose=True):
    level = level or logging.WARNING
    if not handlers:
        handlers = [TqdmHandler()]
        if path:
            os.makedirs(os.path.dirname(path) or './', exist_ok=True)
            handlers.append(logging.FileHandler(path, mode))
    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        level=level,
                        handlers=handlers)
    logger.setLevel(logging.INFO if is_master() and verbose else logging.WARNING)


def progress_bar(iterator,
                 ncols=None,
                 bar_format='{l_bar}{bar:18}| {n_fmt}/{total_fmt} {elapsed}<{remaining}, {rate_fmt}{postfix}',
                 leave=False,
                 **kwargs):
    return tqdm(iterator,
                ncols=ncols,
                bar_format=bar_format,
                ascii=True,
                disable=(not (logger.level == logging.INFO and is_master())),
                leave=leave,
                **kwargs)


logger = get_logger('supar')
