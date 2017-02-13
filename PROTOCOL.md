# UDI Wire Protocol

The UDI protocol encodes messages using [CBOR](cbor.io). Messages are composed
of a single array data item, with a definite length. The first element in the
array is a message type and takes on 3 possible values as an unsigned integer:
request(0), response(1), event(2). Further data items in the array are
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
the first is error code as an unsigned integer and the second is an error message
as a text string.

Responses with a response type of `valid` take on a form dictated by the request
type of the response.

## Events

A event is a single array data item where the first nested item is the unsigned
integer 2. The second data item is an unsigned integer indicating the event type.
The third data item is the thread id for the thread that triggered the event
as an unsigned integer. Further items depend on the event type.

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

### continue

Continues a debuggee with the specified signal. It is an error to send this
request to a thread.

#### Inputs

1. The signal to pass to the debuggee (0 for no signal) as an unsigned integer.

#### Outputs

No outputs.

### read memory

Reads debuggee memory. It is an error to send this request to a thread.

#### Inputs

1. The virtual memory address to read from as an unsigned integer
2. The length of bytes to read as an unsigned integer

#### Outputs

1. The data read as a byte string.

### write memory

Writes debuggee memory. It is an error to send this request to a thread.

#### Inputs

1. The virtual memory address to write to as an unsigned integer
2. The data to write as a byte string.

#### Outputs

No outputs.

### read register

Reads a register from a thread's current context. It is an error to send this request to
a process.

#### Inputs

1. The register to read as an unsigned integer

#### Outputs

1. The register value as an unsigned integer 

### write register

Writes a register in a thread's current context. It is an error to send this request to
a process.

#### Inputs

1. The register to write as an unsigned integer
2. The value to write as an unsigned integer

### state

### init

### create breakpoint

### install breakpoint

### remove breakpoint

### delete breakpoint

### thread suspend

### thread resume

### next instruction

### single step
