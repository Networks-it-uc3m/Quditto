# Quditto Controller

The Quditto Controller (or *qd2_controller*) is the __responsible for emulating the quantum behavior__ of the network within the Quditto digital twin. By default, it leverages [NetSquid](https://netsquid.org/) to simulate quantum hardware and their interactions across the network following QKD protocol implementations. However, users can use any Python simulation platform, although they will need to install it manually on the machine or container that acts as the controller.

## Structure

There are two types of files within the *qd2_controller* package, the core file and the protocol implementations.

### Core file

__The *controller.py* file is the base of the package.__ It is responsible for managing communication with the network nodes and coordinating the execution of quantum protocols. Users will not normally need to modify this file, since __it is designed to work with any quantum protocol implementation.__  To integrate with the controller, protocol scripts must follow some simple rules:

- __Execution interface:__

    - The protocol must be implemented as a __Python script.__
    - It must accept __two numeric arguments:__
        1. The requested __key size.__
        2. The __length of the link__ between the two nodes involved in the key exchange.
        3. Additional modifiable parameters can be defined by the user in the `config.yaml` file. These __additional parameters will be passed to the protocol script as input in the form of a YAML file.__
        
        *__Note:__ the implementation may return a key smaller than the requested size;  if this is the case, the controller will call the script until the generated cryptographic material reaches the required size.If more cryptographic material is returned than required, the controller will not store it. For the moment, if an user wants to implement any type of buffer that stores this excess key, they must implement it themselves.*

- __Output  format:__ 
    - The simulation script must return a __JSON output__ containing the following elements:

        - *__alice_key__*: refers to the key obtained in the source node of the protocol.
        - *__bob_key__*: refers to the key obtained in the receptor node of the protocol.
        - *__time__*: refers to the simulated time. 
        
        *__Note:__ This time is generally longer than the duration of the simulation. In other words, a simulator usually takes less time to generate a key than a pair of real quantum nodes. The controller is designed to wait for the correct time returned by the simulation, i.e., it calculates how much time has passed since the simulation started and how much time remains until the simulated time is reached. Once that time has passed, it returns the keys to the nodes, ensuring realistic emulation of the protocol.*

    *__Note:__ it is not necessary to generate a JSON file, but the simulation output must be given that format.Users may use the following lines at the end of their script:*
    ```
    result = {"alice_key": alice_final_key, "bob_key": bob_final_key, "time": simulated_time}
    print(json.dumps(result))
    ```

### Protocol implementations

The package provides users with two different implementations of BB84, one located in the *bb84_with_eve.py* file, and the other corresponding to the *bb84_att.py* file and the rest of the files inside the [Non_ideal_QKDN](https://github.com/Networks-it-uc3m/Quditto/tree/main/qd2_controller/src/qd2_controller/Non_ideal_QKDN) folder.

- __BB84 with Eve:__
    [TO DO]

- __Extended BB84 (*bb84_att.py*):__
    [TO DO] For the moment, a detailed description of this implementation can be found in the [README](https://github.com/Networks-it-uc3m/Quditto/blob/main/qd2_controller/src/qd2_controller/Non_ideal_QKDN/README.md) inside the Non_ideal_QKDN folder. 
