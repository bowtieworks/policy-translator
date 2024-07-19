# policy-translator



## Getting started

This project exists to take an existing policy in YAML format and convert it to Bowtie format. The script will make the necessary API calls to a Bowtie controller to deploy policy inferred from a YAML file. This will help new customers move existing policy to us faster. The script adapts to our API, so even if the API changes, it should still be able to accomplish the task.

## Requirements

1. A bowtie controller, and you should know it's address.
2. A user with `access policies` and `users` privileges on that controller 
3. A place to run python, with `pyyaml` installed (`pip install pyyaml`). Maybe `requests` too, I forget. 

## Setup and Usage

- Get `policy-translator.py`
- Make sure your .yaml file(s) is in the same directory as the script. 
- Run the script: `python3 policy-translator.py -a bt0.jf-spacex-9998.bowtie.direct -f existing-policy.yaml`
    - `-a` is the base address of the controller 
    - `-f` is your top level .yaml file 

The script will first prompt you to login. This is your admin email and password. 

Next, the script will build policy and then ask you to review and confirm before proceeding. 

Finally, the script will create the policy via API and then ask if you'd like to export the policy for usage on another deployment. 

## Import Policy from Exported
The other file, `import-bowtie-policy-from-json.py` is for usage after the `translator` creates the initial policy in Deployment A, and you want to then get the new policy to Deployment B. You would take the outputted `json` file from the initial creation, and then use the `from-json` script to get the output into Deployment B.

command line: `python3 import-bowtie-policy-from-json.py -a bt0.jf-spacex-9998.bowtie.direct -f bt0.jf-spacex-9998.bowtie.direct-portable-export.json`

## Misc
Reach out to support@bowtie.works if you have any questions or need any assistance.
