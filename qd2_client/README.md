# *Quditto client*

This folder contains the base code for the *quditto client* python package. This package allows a client of the QKD network digital twin deployed by *Quditto* to use the functions described by the standardized [ETSI QKD 004 API](https://portal.etsi.org/webapp/workprogram/Report_WorkItem.asp?WKI_ID=54395), with the exception of the QoS parameters.

## Client004()

This is the main and only class that the package has at the moment. The *Client004* class is capable of *connecting* to a node of the QKD network and using the three functions described in the [ETSI QKD 004 document](https://portal.etsi.org/webapp/workprogram/Report_WorkItem.asp?WKI_ID=54395): *open_connect*, *get_key*, and *close*.

### Functions

- *connect*: connects a *Client004* with a QKD node of the network. A *Client004* can use the other functions of the package on a QKD node only if it is previously connected to it. The *connect* function takes as an argument the IP of the QKD node the client wants to connect to.

- *open_connect*: starts a key stream between two neighbouring QKD nodes. A *Client004* can request a key stream between a QKD node to which it is connected, and a QKD node adjacent to the latter. The *open_connect* function takes as arguments the source, the destination, the key size, the keys time to live, and an ID for the key stream (can be set to *None*, the function will randomly generate one). It returns a response similar to the one described in the [ETSI QKD 004 API](https://portal.etsi.org/webapp/workprogram/Report_WorkItem.asp?WKI_ID=54395), with the exception of the QoS parameters.

- *get_key*: retrieves a key of a specific key stream. A *Client004* can request a key from a key stream that it has *open_connected*. This function takes as arguments the ID of the desired key stream, and the index (optional) of the key. It returns a response as the one described in the [ETSI QKD 004 document](https://portal.etsi.org/webapp/workprogram/Report_WorkItem.asp?WKI_ID=54395).

- *close*: closes a specific key stream. The *close* function takes as an argument the ID of the key stream to close. It returns the status (success or failure) of the *close* request.


A functional test that exemplifies the use of all the functions of this package is located in the [functional test](https://github.com/Networks-it-uc3m/Quditto/tree/main/functional_test) folder.


