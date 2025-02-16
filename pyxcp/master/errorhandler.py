#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Implements error-handling according to XCP spec.
"""
import functools
import logging
import os
import threading
import time
import types
from collections import namedtuple

from pyxcp.errormatrix import Action
from pyxcp.errormatrix import ERROR_MATRIX
from pyxcp.errormatrix import PreAction
from pyxcp.types import COMMAND_CATEGORIES
from pyxcp.types import XcpError
from pyxcp.types import XcpResponseError
from pyxcp.types import XcpTimeoutError


handle_errors = True  # enable/disable XCP error-handling.

logger = logging.getLogger("pyxcp.errorhandler")


class SingletonBase(object):
    _lock = threading.Lock()

    def __new__(cls, *args, **kws):
        # Double-Checked Locking
        if not hasattr(cls, "_instance"):
            try:
                cls._lock.acquire()
                if not hasattr(cls, "_instance"):
                    cls._instance = super(SingletonBase, cls).__new__(cls)
            finally:
                cls._lock.release()
        return cls._instance


Function = namedtuple("Function", "fun arguments")  # store: var | load: var


class InternalError(Exception):
    """Indicates an internal error, like invalid service."""


class UnhandledError(Exception):
    """"""


class UnrecoverableError(Exception):
    """"""


def func_name(func):
    return func.__qualname__ if func is not None else None


def getErrorHandler(service):
    """"""
    return ERROR_MATRIX.get(service)


def getTimeoutHandler(service):
    """"""
    handler = getErrorHandler(service)
    if handler is None:
        raise InternalError("Invalid Service")
    return handler.get(XcpError.ERR_TIMEOUT)


def getActions(service, error_code):
    """"""
    error_str = str(error_code)
    if error_code == XcpError.ERR_TIMEOUT:
        preActions, actions = getTimeoutHandler(service)
    else:
        eh = getErrorHandler(service)
        if eh is None:
            raise InternalError(f"Invalid Service 0x{service:02x}")
        print(f"Try to handle error -- Service: {service.name} Error-Code: {error_code}")
        handler = eh.get(error_str)
        if handler is None:
            raise UnhandledError(f"Service '{service.name}' has no handler for '{error_code}'.")
        preActions, actions = handler
    return preActions, actions


def actionIter(actions):
    """Iterate over action from :file:`errormatrix.py`"""
    if isinstance(actions, (tuple, list)):
        for item in actions:
            yield item
    else:
        yield actions


class Arguments:
    """Container for positional and keyword arguments.

    Parameters
    ----------
        args: tuple
            Positional arguments
        kwargs: dict
            Keyword arguments.
    """

    def __init__(self, args=None, kwargs=None):
        if args is None:
            self.args = ()
        else:
            if not hasattr(args, "__iter__"):
                self.args = (args,)
            else:
                self.args = tuple(args)
        self.kwargs = kwargs or {}

    def __str__(self):
        res = f"{self.__class__.__name__}(ARGS = {self.args}, KWS = {self.kwargs})"
        return res

    def __eq__(self, other):
        return (self.args == other.args if other is not None else ()) and (self.kwargs == other.kwargs if other is not None else {})

    __repr__ = __str__


class Repeater:
    """A required action of some XCP errorhandler is repetition.

    Parameters
    ----------
        initial_value: int
            The actual values are predetermined by XCP:
                - REPEAT (one time)
                - REPEAT_2_TIMES (two times)
                - REPEAT_INF_TIMES ("forever")
    """

    REPEAT = 1
    REPEAT_2_TIMES = 2
    INFINITE = -1

    def __init__(self, initial_value: int):
        self._counter = initial_value
        # print("\tREPEATER ctor", hex(id(self)))

    def repeat(self):
        """Check if repetition is required.

        Returns
        -------
            bool
        """
        # print("\t\tCOUNTER:", hex(id(self)), self._counter)
        if self._counter == Repeater.INFINITE:
            return True
        elif self._counter > 0:
            self._counter -= 1
            return True
        else:
            return False


def display_error():
    """Display error information.

    TODO: callback.

    """


class Handler:
    """"""

    logger = logger

    def __init__(self, instance, func, arguments, error_code=None):
        self.instance = instance
        if hasattr(func, "__closure__") and func.__closure__:
            self.func = func.__closure__[0].cell_contents  # Use original, undecorated function to prevent
            # nasty recursion problems.
        else:
            self.func = func
        self.arguments = arguments
        self.service = self.instance.service
        self.error_code = error_code
        self._repeater = None

    def __str__(self):
        return f"Handler(func = {func_name(self.func)} arguments = {self.arguments} service = {self.service} error_code = {self.error_code})"

    def __eq__(self, other):
        if other is None:
            return False
        return (self.instance == other.instance) and (self.func == other.func) and (self.arguments == other.arguments)

    @property
    def repeater(self):
        # print("\tGet repeater", hex(id(self._repeater)), self._repeater is None)
        return self._repeater

    @repeater.setter
    def repeater(self, value):
        # print("\tSet repeater", hex(id(value)))
        self._repeater = value

    def execute(self):
        self.logger.debug(f"EXECUTE func = {func_name(self.func)} arguments = {self.arguments})")
        if isinstance(self.func, types.MethodType):
            return self.func(*self.arguments.args, **self.arguments.kwargs)
        else:
            return self.func(self.instance, *self.arguments.args, **self.arguments.kwargs)

    def actions(self, preActions, actions):
        """Preprocess errorhandling pre-actions and actions."""
        result_pre_actions = []
        result_actions = []
        repetitionCount = 0
        for item in actionIter(preActions):
            if item == PreAction.NONE:
                pass
            elif item == PreAction.WAIT_T7:
                time.sleep(0.02)  # Completely arbitrary for now.
            elif item == PreAction.SYNCH:
                fn = Function(self.instance.synch, Arguments())
                result_pre_actions.append(fn)
            elif item == PreAction.GET_SEED_UNLOCK:
                raise NotImplementedError("GET_SEED_UNLOCK")
            elif item == PreAction.SET_MTA:
                fn = Function(self.instance.setMta, Arguments(self.instance.mta))
                result_pre_actions.append(fn)
            elif item == PreAction.SET_DAQ_PTR:
                fn = Function(self.instance.setDaqPtr, Arguments(self.instance.currentDaqPtr))
            elif item == PreAction.START_STOP_X:
                raise NotImplementedError("START_STOP_X")
            elif item == PreAction.REINIT_DAQ:
                raise NotImplementedError("REINIT_DAQ")
            elif item == PreAction.DISPLAY_ERROR:
                pass
            elif item == PreAction.DOWNLOAD:
                raise NotImplementedError("DOWNLOAD")
            elif item == PreAction.PROGRAM:
                raise NotImplementedError("PROGRAM")
            elif item == PreAction.UPLOAD:
                raise NotImplementedError("UPLOAD")
            elif item == PreAction.UNLOCK_SLAVE:
                resource = COMMAND_CATEGORIES.get(self.instance.service)  # noqa: F841
                raise NotImplementedError("UNLOCK_SLAVE")
        for item in actionIter(actions):
            if item == Action.NONE:
                pass
            elif item == Action.DISPLAY_ERROR:
                raise UnhandledError("Could not proceed due to unhandled error.")
            elif item == Action.RETRY_SYNTAX:
                raise UnhandledError("Could not proceed due to unhandled error.")
            elif item == Action.RETRY_PARAM:
                raise UnhandledError("Could not proceed due to unhandled error.")
            elif item == Action.USE_A2L:
                raise UnhandledError("Could not proceed due to unhandled error.")
            elif item == Action.USE_ALTERATIVE:
                raise UnhandledError("Could not proceed due to unhandled error.")  # TODO: check alternatives.
            elif item == Action.REPEAT:
                repetitionCount = Repeater.REPEAT
            elif item == Action.REPEAT_2_TIMES:
                repetitionCount = Repeater.REPEAT_2_TIMES
            elif item == Action.REPEAT_INF_TIMES:
                repetitionCount = Repeater.INFINITE
            elif item == Action.RESTART_SESSION:
                raise UnhandledError("Could not proceed due to unhandled error.")
            elif item == Action.TERMINATE_SESSION:
                raise UnhandledError("Could not proceed due to unhandled error.")
            elif item == Action.SKIP:
                pass
            elif item == Action.NEW_FLASH_WARE:
                raise UnhandledError("Could not proceed due to unhandled error")
        return result_pre_actions, result_actions, Repeater(repetitionCount)


class HandlerStack:
    """"""

    def __init__(self):
        self._stack = []

    def push(self, handler):
        if handler != self.tos():
            self._stack.append(handler)

    def pop(self):
        if len(self) > 0:
            self._stack.pop()

    def tos(self):
        if len(self) > 0:
            return self._stack[-1]
        else:
            return None

    def empty(self):
        return self._stack == []

    def __len__(self):
        return len(self._stack)

    def __repr__(self):
        result = []
        for idx in range(len(self)):
            result.append(str(self[idx]))
        return "\n".join(result)

    def __getitem__(self, ndx):
        return self._stack[ndx]

    __str__ = __repr__


class Executor(SingletonBase):
    """"""

    handlerStack = HandlerStack()
    repeater = None
    logger = logger
    previous_error_code = None
    error_code = None
    func = None
    arguments = None

    def __call__(self, inst, func, arguments):
        self.logger.debug(f"__call__({func.__qualname__})")
        self.inst = inst
        self.func = func
        self.arguments = arguments
        handler = Handler(inst, func, arguments)
        self.handlerStack.push(handler)
        # print("\tENTER handler:", hex(id(handler)))
        try:
            while True:
                try:
                    handler = self.handlerStack.tos()
                    # print("\t\tEXEC", hex(id(handler)))
                    res = handler.execute()
                except XcpResponseError as e:
                    self.logger.error(f"XcpResponseError [{str(e)}]")
                    self.error_code = e.get_error_code()
                except XcpTimeoutError as e:
                    self.logger.error(f"XcpTimeoutError [{str(e)}]")
                    self.error_code = XcpError.ERR_TIMEOUT
                except Exception as e:
                    raise UnrecoverableError(f"Don't know how to handle exception '{repr(e)}'") from e
                else:
                    self.error_code = None
                    # print("\t\t\t*** SUCCESS ***")
                    self.handlerStack.pop()
                    if self.handlerStack.empty():
                        # print("OK, all handlers passed: '{}'.".format(res))
                        return res

                if self.error_code is not None:
                    preActions, actions, repeater = handler.actions(*getActions(inst.service, self.error_code))
                    if handler.repeater is None:
                        handler.repeater = repeater
                    for f, a in reversed(preActions):
                        self.handlerStack.push(Handler(inst, f, a, self.error_code))
                self.previous_error_code = self.error_code
                if handler.repeater:
                    if handler.repeater.repeat():
                        continue
                    else:
                        raise UnrecoverableError(
                            f"Max. repetition count reached while trying to execute service '{handler.func.__name__}'."
                        )
        finally:
            # cleanup of class variables
            self.previous_error_code = None
            while not self.handlerStack.empty():
                self.handlerStack.pop()
            self.error_code = None
            self.func = None
            self.arguments = None


def disable_error_handling(value: bool):
    """Disable XCP error-handling (mainly for performance reasons)."""

    global handle_errors
    handle_errors = not bool(value)


def wrapped(func):
    """This decorator is XCP error-handling enabled."""

    @functools.wraps(func)
    def inner(*args, **kwargs):
        if handle_errors:
            inst = args[0]  # First parameter is 'self'.
            arguments = Arguments(args[1:], kwargs)
            executor = Executor()
            res = executor(inst, func, arguments)
        else:
            res = func(*args, **kwargs)
        return res

    return inner
