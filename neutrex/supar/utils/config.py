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

import argparse
import os
from ast import literal_eval
from configparser import ConfigParser

import supar
from supar.utils.fn import download


class Config(object):

    def __init__(self, **kwargs):
        super(Config, self).__init__()

        self.update(kwargs)

    def __repr__(self):
        s = line = "-" * 20 + "-+-" + "-" * 30 + "\n"
        s += f"{'Param':20} | {'Value':^30}\n" + line
        for name, value in vars(self).items():
            s += f"{name:20} | {str(value):^30}\n"
        s += line

        return s

    def __getitem__(self, key):
        return getattr(self, key)

    def __contains__(self, key):
        return hasattr(self, key)

    def __getstate__(self):
        return vars(self)

    def __setstate__(self, state):
        self.__dict__.update(state)

    def keys(self):
        return vars(self).keys()

    def items(self):
        return vars(self).items()

    def update(self, kwargs):
        for key in ('self', 'cls', '__class__'):
            kwargs.pop(key, None)
        kwargs.update(kwargs.pop('kwargs', dict()))
        for name, value in kwargs.items():
            setattr(self, name, value)
        return self

    def get(self, key, default=None):
        return getattr(self, key) if hasattr(self, key) else default

    def pop(self, key, val=None):
        return self.__dict__.pop(key, val)

    @classmethod
    def load(cls, conf='', unknown=None, **kwargs):
        config = ConfigParser()
        config.read(conf if not conf or os.path.exists(conf) else download(supar.CONFIG['github'].get(conf, conf)))
        config = dict((name, literal_eval(value))
                      for section in config.sections()
                      for name, value in config.items(section))
        if unknown is not None:
            parser = argparse.ArgumentParser()
            for name, value in config.items():
                parser.add_argument('--'+name.replace('_', '-'), type=type(value), default=value)
            config.update(vars(parser.parse_args(unknown)))
        config.update(kwargs)
        return cls(**config)
