This project examines login activity and seeks signs of suspicious behavior.  
I built a small detection system in Python that checks for three types of unusual activity:

1. **Impossible Travel** – a user logs in from two faraway places too quickly  
2. **Off-Hours Admin Activity** – an admin account is used late at night or outside normal work hours  
3. **Brute Force / Password Spray** – many failed login attempts on one user or from one IP  

The script reads two files:
- `auth_events.csv` — login events  
- `ground_truth.csv` — real attacks (used to check accuracy)

After running all detectors, the script shows:
- how many real attacks it caught  
- how many false alarms it produced  
- how many attacks it missed  
- **precision** (how accurate alerts are)  
- **recall** (how many real attacks were found)

  ### Example Output
True positives: 4
False positives: 1
False negatives: 6
Precision: 0.80
Recall: 0.40

  
### How to Run
Clone the repo and run:
python3 code/catch.py code/auth_events.csv --truth code/ground_truth.csv
