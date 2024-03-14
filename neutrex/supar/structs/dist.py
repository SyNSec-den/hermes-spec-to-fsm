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

import torch
import torch.autograd as autograd
from supar.structs.semiring import (CrossEntropySemiring, EntropySemiring,
                                    KLDivergenceSemiring, KMaxSemiring,
                                    LogSemiring, MaxSemiring, SampledSemiring)
from torch.distributions.distribution import Distribution
from torch.distributions.utils import lazy_property


class StructuredDistribution(Distribution):
    r"""
    Base class for structured distribution :math:`p(y)` :cite:`eisner-2016-inside,goodman-1999-semiring,li-eisner-2009-first`.

    Args:
        scores (torch.Tensor):
            Log potentials, also for high-order cases.

    """

    def __init__(self, scores, **kwargs):
        self.scores = scores.requires_grad_() if isinstance(scores, torch.Tensor) else [s.requires_grad_() for s in scores]
        self.kwargs = kwargs

    def __repr__(self):
        return f"{self.__class__.__name__}()"

    def __add__(self, other):
        return self.__class__(torch.stack((self.scores, other.scores), -1), lens=self.lens)

    @lazy_property
    def log_partition(self):
        r"""
        Computes the log partition function of the distribution :math:`p(y)`.
        """

        return self.forward(LogSemiring)

    @lazy_property
    def marginals(self):
        r"""
        Computes marginal probabilities of the distribution :math:`p(y)`.
        """

        return self.backward(self.log_partition.sum())

    @lazy_property
    def max(self):
        r"""
        Computes the max score of the distribution :math:`p(y)`.
        """

        return self.forward(MaxSemiring)

    @lazy_property
    def argmax(self):
        r"""
        Computes :math:`\arg\max_y p(y)` of the distribution :math:`p(y)`.
        """
        raise NotImplementedError

    @lazy_property
    def mode(self):
        return self.argmax

    def kmax(self, k):
        r"""
        Computes the k-max of the distribution :math:`p(y)`.
        """

        return self.forward(KMaxSemiring(k))

    def topk(self, k):
        r"""
        Computes the k-argmax of the distribution :math:`p(y)`.
        """
        raise NotImplementedError

    def sample(self):
        r"""
        Obtains a structured sample from the distribution :math:`y \sim p(y)`.
        TODO: multi-sampling.
        """

        return self.backward(self.forward(SampledSemiring).sum()).detach()

    @lazy_property
    def entropy(self):
        r"""
        Computes entropy :math:`H[p]` of the distribution :math:`p(y)`.
        """

        return self.forward(EntropySemiring)

    def cross_entropy(self, other):
        r"""
        Computes cross-entropy :math:`H[p,q]` of self and another distribution.

        Args:
            other (~supar.structs.dist.StructuredDistribution): Comparison distribution.
        """

        return (self + other).forward(CrossEntropySemiring)

    def kl(self, other):
        r"""
        Computes KL-divergence :math:`KL[p \parallel q]=H[p,q]-H[p]` of self and another distribution.

        Args:
            other (~supar.structs.dist.StructuredDistribution): Comparison distribution.
        """

        return (self + other).forward(KLDivergenceSemiring)

    def log_prob(self, value, **kwargs):
        """
        Computes log probability over values :math:`p(y)`.
        """

        return self.score(value, **kwargs) - self.log_partition

    def score(self, value):
        raise NotImplementedError

    @torch.enable_grad()
    def forward(self, semiring):
        raise NotImplementedError

    def backward(self, log_partition):
        return autograd.grad(log_partition,
                             self.scores if isinstance(self.scores, torch.Tensor) else self.scores[0],
                             create_graph=True)[0]
