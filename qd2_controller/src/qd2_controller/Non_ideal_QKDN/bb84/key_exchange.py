from bb84_protocol import FULL_BB84
import sys
import logging
import yaml
import json

if __name__ == "__main__":

    if len(sys.argv) == 2:
        params = str(sys.argv[1])

    with open(params, "r") as f:
        PARAMETER_VALUES_0 = yaml.safe_load(f)


    # Ejecutar el experimento BB84
    output_message_CP, dc = FULL_BB84(PARAMETER_VALUES_0)

    simulated_time = dc.dataframe["Total protocol duration (s)"].iloc[-1]
    alice_final_key = output_message_CP
    bob_final_key = output_message_CP
    alice_final_key = [int(x) for x in alice_final_key]
    bob_final_key = [int(x) for x in bob_final_key]

    result = {"alice_key": alice_final_key, "bob_key": bob_final_key, "time": simulated_time}

    print(json.dumps(result))