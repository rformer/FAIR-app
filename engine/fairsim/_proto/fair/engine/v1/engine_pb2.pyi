from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class InfoRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class EngineInfo(_message.Message):
    __slots__ = ("version", "architecture", "validation")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    ARCHITECTURE_FIELD_NUMBER: _ClassVar[int]
    VALIDATION_FIELD_NUMBER: _ClassVar[int]
    version: str
    architecture: str
    validation: Validation
    def __init__(self, version: _Optional[str] = ..., architecture: _Optional[str] = ..., validation: _Optional[_Union[Validation, _Mapping]] = ...) -> None: ...

class Validation(_message.Message):
    __slots__ = ("suite_version", "passed", "run_at_unix_ms", "detail_json")
    SUITE_VERSION_FIELD_NUMBER: _ClassVar[int]
    PASSED_FIELD_NUMBER: _ClassVar[int]
    RUN_AT_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    DETAIL_JSON_FIELD_NUMBER: _ClassVar[int]
    suite_version: str
    passed: bool
    run_at_unix_ms: int
    detail_json: str
    def __init__(self, suite_version: _Optional[str] = ..., passed: _Optional[bool] = ..., run_at_unix_ms: _Optional[int] = ..., detail_json: _Optional[str] = ...) -> None: ...

class SimulateRequest(_message.Message):
    __slots__ = ("bundle", "seed", "iterations", "control_sets", "convergence_threshold_bp", "run_id")
    BUNDLE_FIELD_NUMBER: _ClassVar[int]
    SEED_FIELD_NUMBER: _ClassVar[int]
    ITERATIONS_FIELD_NUMBER: _ClassVar[int]
    CONTROL_SETS_FIELD_NUMBER: _ClassVar[int]
    CONVERGENCE_THRESHOLD_BP_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    bundle: bytes
    seed: int
    iterations: int
    control_sets: _containers.RepeatedScalarFieldContainer[str]
    convergence_threshold_bp: int
    run_id: str
    def __init__(self, bundle: _Optional[bytes] = ..., seed: _Optional[int] = ..., iterations: _Optional[int] = ..., control_sets: _Optional[_Iterable[str]] = ..., convergence_threshold_bp: _Optional[int] = ..., run_id: _Optional[str] = ...) -> None: ...

class SimulateEvent(_message.Message):
    __slots__ = ("progress", "result", "series", "done", "failure")
    PROGRESS_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    SERIES_FIELD_NUMBER: _ClassVar[int]
    DONE_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    progress: Progress
    result: ControlSetResult
    series: SeriesChunk
    done: Done
    failure: Failure
    def __init__(self, progress: _Optional[_Union[Progress, _Mapping]] = ..., result: _Optional[_Union[ControlSetResult, _Mapping]] = ..., series: _Optional[_Union[SeriesChunk, _Mapping]] = ..., done: _Optional[_Union[Done, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class Progress(_message.Message):
    __slots__ = ("done", "total")
    DONE_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    done: int
    total: int
    def __init__(self, done: _Optional[int] = ..., total: _Optional[int] = ...) -> None: ...

class ControlSetResult(_message.Message):
    __slots__ = ("control_set", "summary_json")
    CONTROL_SET_FIELD_NUMBER: _ClassVar[int]
    SUMMARY_JSON_FIELD_NUMBER: _ClassVar[int]
    control_set: str
    summary_json: str
    def __init__(self, control_set: _Optional[str] = ..., summary_json: _Optional[str] = ...) -> None: ...

class SeriesChunk(_message.Message):
    __slots__ = ("control_set", "offset", "values")
    CONTROL_SET_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    control_set: str
    offset: int
    values: bytes
    def __init__(self, control_set: _Optional[str] = ..., offset: _Optional[int] = ..., values: _Optional[bytes] = ...) -> None: ...

class Done(_message.Message):
    __slots__ = ("warnings",)
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    warnings: _containers.RepeatedCompositeFieldContainer[Warning]
    def __init__(self, warnings: _Optional[_Iterable[_Union[Warning, _Mapping]]] = ...) -> None: ...

class Warning(_message.Message):
    __slots__ = ("code", "pointer", "control_set", "detail")
    CODE_FIELD_NUMBER: _ClassVar[int]
    POINTER_FIELD_NUMBER: _ClassVar[int]
    CONTROL_SET_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    code: str
    pointer: str
    control_set: str
    detail: str
    def __init__(self, code: _Optional[str] = ..., pointer: _Optional[str] = ..., control_set: _Optional[str] = ..., detail: _Optional[str] = ...) -> None: ...

class Failure(_message.Message):
    __slots__ = ("code", "detail")
    CODE_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    code: str
    detail: str
    def __init__(self, code: _Optional[str] = ..., detail: _Optional[str] = ...) -> None: ...

class AggregateInput(_message.Message):
    __slots__ = ("header", "series")
    HEADER_FIELD_NUMBER: _ClassVar[int]
    SERIES_FIELD_NUMBER: _ClassVar[int]
    header: AggregateHeader
    series: MemberChunk
    def __init__(self, header: _Optional[_Union[AggregateHeader, _Mapping]] = ..., series: _Optional[_Union[MemberChunk, _Mapping]] = ...) -> None: ...

class AggregateHeader(_message.Message):
    __slots__ = ("aggregate_id", "seed", "iterations", "members")
    AGGREGATE_ID_FIELD_NUMBER: _ClassVar[int]
    SEED_FIELD_NUMBER: _ClassVar[int]
    ITERATIONS_FIELD_NUMBER: _ClassVar[int]
    MEMBERS_FIELD_NUMBER: _ClassVar[int]
    aggregate_id: str
    seed: int
    iterations: int
    members: _containers.RepeatedCompositeFieldContainer[Member]
    def __init__(self, aggregate_id: _Optional[str] = ..., seed: _Optional[int] = ..., iterations: _Optional[int] = ..., members: _Optional[_Iterable[_Union[Member, _Mapping]]] = ...) -> None: ...

class Member(_message.Message):
    __slots__ = ("position", "run_id", "control_set", "scenario_name")
    POSITION_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    CONTROL_SET_FIELD_NUMBER: _ClassVar[int]
    SCENARIO_NAME_FIELD_NUMBER: _ClassVar[int]
    position: int
    run_id: str
    control_set: str
    scenario_name: str
    def __init__(self, position: _Optional[int] = ..., run_id: _Optional[str] = ..., control_set: _Optional[str] = ..., scenario_name: _Optional[str] = ...) -> None: ...

class MemberChunk(_message.Message):
    __slots__ = ("position", "offset", "values")
    POSITION_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    position: int
    offset: int
    values: bytes
    def __init__(self, position: _Optional[int] = ..., offset: _Optional[int] = ..., values: _Optional[bytes] = ...) -> None: ...

class AggregateEvent(_message.Message):
    __slots__ = ("progress", "result", "series", "done", "failure")
    PROGRESS_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    SERIES_FIELD_NUMBER: _ClassVar[int]
    DONE_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    progress: Progress
    result: AggregateResult
    series: SeriesChunk
    done: Done
    failure: Failure
    def __init__(self, progress: _Optional[_Union[Progress, _Mapping]] = ..., result: _Optional[_Union[AggregateResult, _Mapping]] = ..., series: _Optional[_Union[SeriesChunk, _Mapping]] = ..., done: _Optional[_Union[Done, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class AggregateResult(_message.Message):
    __slots__ = ("summary_json",)
    SUMMARY_JSON_FIELD_NUMBER: _ClassVar[int]
    summary_json: str
    def __init__(self, summary_json: _Optional[str] = ...) -> None: ...
