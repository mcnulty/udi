# UDI Wire Protocol

The UDI protocol encodes messages using [CBOR](cbor.io). Messages are composed
of a single array data item, with a definite length. The first element in the
array is a message type and takes on 3 possible values as an unsigned integer:
`request(0)`, `response(1)`, `event(2)`. Further data items in the array are
determined by the message type.

## Requests

A request is a single array data item where the first nested item is the unsigned
integer 0. The second data item is an unsigned integer indicating the request
type. Further data items are input data required to execute on the request.

The following is a list of request types and corresponding values:

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

## Responses

A response is a single array data item where the first nested item is the unsigned
integer 1. The second data item is an unsigned integer indicating the response
type. The third data item is an unsigned integer indicating the request type of
the request for which the response was produced.

The following is a list of response types and corresponding values:

| Response Type | Value |
| ------------- | ----- |
| valid         | 0     |
| error         | 1     |

Responses with a response type of `error` always have two additional data items:

1. An error code as an unsigned integer
2. An error message as a text string

Responses with a response type of `valid` take on a form dictated by the request
type of the response.

## Events

An event is a single array data item where the first nested item is the
unsigned integer 2. The second data item is an unsigned integer indicating the
event type.  The third data item is the thread id as an unsigned integer for
the thread that triggered the event. Further items depend on the event type.

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

## Request and Response Data

**continue**

Continues a debuggee with the specified signal. It is an error to send this
request to a thread.

_Inputs_

1. The signal to pass to the debuggee (0 for no signal) as an unsigned integer.

_Outputs_

No outputs.

**read memory**

Reads debuggee memory. It is an error to send this request to a thread.

_Inputs_

1. The virtual memory address to read from as an unsigned integer
2. The length of bytes to read as an unsigned integer

_Outputs_

1. The data read as a byte string.

**write memory**

Writes debuggee memory. It is an error to send this request to a thread.

_Inputs_

1. The virtual memory address to write to as an unsigned integer
2. The data to write as a byte string.

_Outputs_

No outputs.

**read register**

Reads a register from a thread's current context. It is an error to send this request to
a process.

_Inputs_

1. The register to read as an unsigned integer

_Outputs_

1. The register value as an unsigned integer

**write register**

Writes a register in a thread's current context. It is an error to send this request to
a process.

_Inputs_

1. The register to write as an unsigned integer
2. The value to write as an unsigned integer

_Outputs_

No outputs.

**state**

Retrieves the state of the threads in a process. It is an error to send this request to
a process.

_Inputs_

No inputs.

_Outputs_

1. Thread id as an unsigned integer
2. Thread state as an unsigned integer

**init**

Complete the initialization of a debuggee.

_Inputs_

No inputs.

_Outputs_

1. The UDI protocol version as an unsigned integer
2. The architecture of the debuggee as an unsigned integer
3. A non-zero unsigned integer if the debuggee multithread capable
4. The tid for the initial thread as an unsigned integer

**create breakpoint**

Creates a breakpoint

_Inputs_

1. The address of the breakpoint as an unsigned integer

_Outputs_

No outputs.

**install breakpoint**

Install the breakpoint into memory.

_Inputs_

1. The address of the breakpoint as an unsigned integer

_Outputs_

No outputs.

**remove breakpoint**

Removes the breakpoint from memory.

_Inputs_

1. The address of the breakpoint as an unsigned integer

_Outputs_

No outputs.

**delete breakpoint**

Delete the breakpoint

_Inputs_

1. The address of the breakpoint as an unsigned integer

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

1. The address of the next instruction as an unsigned integer

**single step**

Change the single step setting for a thread. It is an error to send this request to
a process.

_Inputs_

1. A non-zero unsigned integer when single stepping to be enabled for the thread

_Outputs_

1. The previous setting as an unsigned integer

## Event Data

**error**

1. The error message as a text string

**signal**

1. The virtual address where the signal occurred as an unsigned integer
2. The signal number as an unsigned integer

**breakpoint**

1. The virtual address where the breakpoint occurred as an unsigned integer

**thread create**

1. The thread id for the newly created thread as an unsigned integer

**thread death**

No data.

**process exit**

1. The exit code from the process exit as an unsigned integer.

**process fork**

1. The process id for the new process as an unsigned integer.

**process exec**

1. The path to the new executable image as a text string
2. The arguments to the new execution as an array of text strings
3. The environment for the new execution as an array of text strings

**single step**

No data.

**process cleanup**

No data.
