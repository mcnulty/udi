# UDI Wire Protocol

The UDI protocol encodes messages using [CBOR](cbor.io). There are three types of messages:
`request`, `response`, or `event`. The message type is determined by the source or destination of
the message.

## Requests

A request is a single map data item with one guaranteed pair:

- A key of `type` with an unsigned integer value that defines the type of the request.

The possible values are in the table below:

| Request Type        | Value |
| ------------        | ----- |
| continue            | 0     |
| read memory         | 1     |
| write memory        | 2     |
| read register       | 3     |
| write register      | 4     |
| state               | 5     |
| init                | 6     |
| create breakpoint   | 7     |
| install breakpoint  | 8     |
| remove breakpoint   | 9     |
| delete breakpoint   | 10    |
| thread suspend      | 11    |
| thread resume       | 12    |
| next instruction    | 13    |
| single step         | 14    |

Each request type defines further pairs to be included in the map.

## Responses

A response is composed of three data items. The first two items always take on the following form:

1. An unsigned integer value that defines the type of the response 
2. An unsigned integer value that defines the type of the corresponding request

The following is a list of response types and corresponding values:

| Response Type | Value |
| ------------- | ----- |
| valid         | 0     |
| error         | 1     |

When the response type is `error`, the third data item is a map with the following pairs:

| Key   | Value            | Description      |
| ----- | ---------------- | -------------    | 
| code  | unsigned integer | An error code    |
| msg   | text string      | An error message |

Responses with a response type of `valid` have a third data item that is a map. The pairs in
the map are dictated by the type of the request.

## Events

An event is composed of three data items. The first two items always take on the following
form:

1. An unsigned integer value that defines the type of the event.
2. An unsigned integer value that identifies tid of the thread that triggered the event.

The following is a list of event types and corresponding values:

| Event Type      | Value |
| ----------      | ----- |
| error           | 0 |
| signal          | 1 |
| breakpoint      | 2 |
| thread create   | 3 |
| thread death    | 4 |
| process exit    | 5 |
| process fork    | 6 |
| process exec    | 7 |
| single step     | 8 |
| process cleanup | 9 |

The third data item is a map and its pairs are defined by the event type.

## Request and Response Data

**continue**

Continues a debuggee with the specified signal. It is an error to send this
request to a thread.

_Inputs_

- `sig`: The signal to pass to the debuggee (0 for no signal) as an unsigned integer.

_Outputs_

No outputs.

**read memory**

Reads debuggee memory. It is an error to send this request to a thread.

_Inputs_

- `addr`: The virtual memory address to read from as an unsigned integer
- `len`: The length of bytes to read as an unsigned integer

_Outputs_

- `data`: The data read as a byte string.

**write memory**

Writes debuggee memory. It is an error to send this request to a thread.

_Inputs_

- `addr`: The virtual memory address to write to as an unsigned integer
- `data`: The data to write as a byte string.

_Outputs_

No outputs.

**read register**

Reads a register from a thread's current context. It is an error to send this request to
a process.

_Inputs_

- `reg`: The register to read as an unsigned integer

_Outputs_

- `value`: The register value as an unsigned integer

**write register**

Writes a register in a thread's current context. It is an error to send this request to
a process.

_Inputs_

- `reg`: The register to write as an unsigned integer
- `value`: The value to write as an unsigned integer

_Outputs_

No outputs.

**state**

Retrieves the state of the threads in a process. It is an error to send this request to
a process.

_Inputs_

No inputs.

_Outputs_

- `tid`: Thread id as an unsigned integer
- `state`: Thread state as an unsigned integer

**init**

Complete the initialization of a debuggee.

_Inputs_

No inputs.

_Outputs_

- `v`: The UDI protocol version as an unsigned integer
- `arch`: The architecture of the debuggee as an unsigned integer
- `mt`: A non-zero unsigned integer if the debuggee is multithread capable
- `tid`: The tid for the initial thread as an unsigned integer

**create breakpoint**

Creates a breakpoint

_Inputs_

- `addr`: The address of the breakpoint as an unsigned integer

_Outputs_

No outputs.

**install breakpoint**

Install the breakpoint into memory.

_Inputs_

- `addr`: The address of the breakpoint as an unsigned integer

_Outputs_

No outputs.

**remove breakpoint**

Removes the breakpoint from memory.

_Inputs_

- `addr`: The address of the breakpoint as an unsigned integer

_Outputs_

No outputs.

**delete breakpoint**

Delete the breakpoint

_Inputs_

- `addr`: The address of the breakpoint as an unsigned integer

_Outputs_

No outputs.

**thread suspend**

Mark a thread suspended. It is an error to send this request to a process.

_Inputs_

No inputs.

_Outputs_

No outputs.

**thread resume**

Mark a thread resumed. It is an error to send this request to a process.

_Inputs_

No inputs.

_Outputs_

No outputs.

**next instruction**

Retrieves the address of the next instruction to be executed.

_Inputs_

No inputs.

_Outputs_

- `addr`: The address of the next instruction as an unsigned integer

**single step**

Change the single step setting for a thread. It is an error to send this request to
a process.

_Inputs_

- `value`: A non-zero unsigned integer when single stepping to be enabled for the thread

_Outputs_

- `value`: The previous setting as an unsigned integer

## Event Data

**error**

- `msg`: The error message as a text string

**signal**

- `addr`: The virtual address where the signal occurred as an unsigned integer
- `sig`: The signal number as an unsigned integer

**breakpoint**

- `addr`: The virtual address where the breakpoint occurred as an unsigned integer

**thread create**

- `tid`: The thread id for the newly created thread as an unsigned integer

**thread death**

No data.

**process exit**

- `code`: The exit code from the process exit as an unsigned integer.

**process fork**

- `pid`: The process id for the new process as an unsigned integer.

**process exec**

- `path`: The path to the new executable image as a text string
- `argv`: The arguments to the new execution as an array of text strings
- `envp`: The environment for the new execution as an array of text strings

**single step**

No data.

**process cleanup**

No data.
