import sys
import os


from Non_ideal_QKDN.bb84.bb84_protocol import FULL_BB84
import logging
import yaml
import json

if __name__ == "__main__":

    if len(sys.argv) == 4:
        desired_key_length = int(sys.argv[1])
        distance = float(sys.argv[2])
        params = str(sys.argv[3])

    with open(params, "r") as f:
        PARAMETER_VALUES = yaml.safe_load(f)

    PARAMETER_VALUES["distance"] = distance
    PARAMETER_VALUES["required_length"] = desired_key_length
        


    # Ejecutar el experimento BB84
    output_message_CP, dc = FULL_BB84(PARAMETER_VALUES)

    simulated_time = dc.dataframe["Total protocol duration (s)"].iloc[-1]
    alice_final_key = output_message_CP
    bob_final_key = output_message_CP
    alice_final_key = [int(x) for x in alice_final_key]
    bob_final_key = [int(x) for x in bob_final_key]

    result = {"alice_key": alice_final_key, "bob_key": bob_final_key, "time": simulated_time}

    print(json.dumps(result))