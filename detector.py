import pandas as pd

from db import save_alerts, save_events

LOG_FILE = "data/security_logs.csv"

def load_logs():
	logs = pd.read_csv(LOG_FILE)

	logs["timestamp"] = pd.to_datetime(logs["timestamp"])

	logs = logs.sort_values("timestamp")
	
	return logs

def detect_brute_force(logs, threshold=5, window_minutes=10):

	failed_logins = logs[
		(logs["event_type"]== "login") &
		(logs["status"] == "failed")
	].copy()

	detections = []

	for (source_ip, username), group in failed_logins.groupby(
		["source_ip", "username"]
	):
		group = group.sort_values("timestamp")

		timestamps = group["timestamp"].tolist()

		left = 0

		for right in range(len(timestamps)):

			while (
				timestamps[right] - timestamps[left]
				> pd.Timedelta(minutes=window_minutes)
			):
				left += 1

			failed_attempts = right - left + 1

			if failed_attempts >= threshold:

				detections.append({
					"source_ip": source_ip,
					"username": username,
					"failed_attempts": failed_attempts,
					"window_start": timestamps[left],
					"window_end": timestamps[right]
				})

				break

			return pd.DataFrame(
				detections,
				columns=[
					"source-ip",
					"username",
					"failed_attempts",
					"window_start",
					"window_end"
				]
			)
		

def detect_possible_compromise(logs, threshold=5):
	alerts = []

	grouped_logs = logs.groupby(["source_ip", "username"])

	for (source_ip, username), group in grouped_logs:

		group = group.sort_values("timestamp")

		failed_count = 0

		for _, event in group.iterrows():

			if event["event_type"] != "login":
				continue

			if event["status"] == "failed":
				failed_count += 1

			elif event["status"] == "success":

				if failed_count >= threshold:

					alerts.append({
						"source_ip": source_ip,
						"username": username,
						"failed_attempts": failed_count,
						"successful_login": event["timestamp"],
						"severity": "HIGH"
					})

				failed_count = 0

		return pd.DataFrame(alerts)

def detect_password_spray(logs, user_threshold=3, window_minutes=10):

	failed_logins = logs[
		(logs["event_type"] == "login") &
		(logs["status"] == "failed") 
	].copy()

	detections = []

	for source_ip, group in failed_logins.groupby("source_ip"):

		group = group.sort_values("timestamp")

		events = list(
			group[["timestamp", "username"]]
			.itertuples(index=False, name=None)
		)

		left = 0

		for right in range(len(events)):

			while (
				events[right][0] - events[left][0]
				> pd.Timedelta(minutes=window_minutes)
			):
				left += 1

			window_events = events[left:right + 1]

			unique_users = len(
				{username for _, username in window_events}
			)

			if unique_users >= user_threshold:

				detections.append({ 
					"source_ip": source_ip,
					"unique_users": unique_users,
					"window_start": events[left][0],
					"window_end": events[right][0]
				})

				break

	return pd.DataFrame(
		detections,
		columns=[
			"source_ip",
			"unique_users",
			"window_start",
			"window_end"
		]
	) 
	

def create_alert(rule_id, alert_type, severity, source_ip, username, description):
	return {
		"rule_id": rule_id,
		"alert_type": alert_type,
		"severity": severity,
		"source_ip": source_ip,
		"username": username,
		"description": description
	}
def generate_brute_force_alerts(logs):
	detections = detect_brute_force(logs)

	alerts = []

	for _, row in detections.iterrows():

		alert = create_alert(
			rule_id="AUTH-001",
			alert_type="Brute Force",
			severity="HIGH",
			source_ip=row["source_ip"],
			username=row["username"],
			description=f'{row["failed_attempts"]} failed login attempts detected.'
		)

		alerts.append(alert)

	return alerts
def generate_compromise_alerts(logs):
	detections = detect_possible_compromise(logs)

	alerts = []

	for _, row in detections.iterrows():

		alert = create_alert(
		rule_id="AUTH-002",
		alert_type="Possible Account Compromise",
		severity="CRITICAL",
		source_ip=row["source_ip"],
		username=row["username"],
		description=(
			f'{row["failed_attempts"]} failed attempts '
			f'followed by successful login.'
			)
		)

		alerts.append(alert)

	return alerts

def generate_password_spray_alerts(logs):
    detections = detect_password_spray(logs)

    alerts = []

    for _, row in detections.iterrows():

        alert = create_alert(
            rule_id="AUTH-003",
            alert_type="Password Spray",
            severity="HIGH",
            source_ip=row["source_ip"],
            username="Multiple Users",
            description=(
                f'{row["unique_users"]} different accounts '
                f'were targeted from the same IP.'
            )
        )

        alerts.append(alert)

    return alerts

def generate_all_alerts(logs):

    alerts = []

    alerts.extend(generate_brute_force_alerts(logs))
    alerts.extend(generate_compromise_alerts(logs))
    alerts.extend(generate_password_spray_alerts(logs))

    return alerts

def main():
	
	logs = load_logs()

	saved_events = save_events(logs)

	print(f"\nSaved {saved_events} new events to PostgreSQL.")

	print("MiniSOC Security Log Analyzer")
	print("----------------------------")

	print(f"Total events loaded: {len(logs)}")
	
	brute_force_alerts = detect_brute_force(logs)
	
	print("\nBrute Force Detection:")
	print("-----------------------")

	if brute_force_alerts.empty:
		print("No brute force activity detected.")

	else:
		print("WARNING: Possible brute force activity detected!")
		print(brute_force_alerts)

	compromise_alerts = detect_possible_compromise(logs)

	print("\nPossible Account Compromise Detection:")
	print("---------------------------------------")

	if compromise_alerts.empty:
		print("No possible account compromise detected.")

	else:
		print("CRITICAL: Failed attempts followed by successful login!")
		print(compromise_alerts)

	spray_alerts = detect_password_spray(logs)

	print("\nPassword Spray Detection:")
	print("--------------------------")

	if spray_alerts.empty:
		print("No password spraying detected.")

	else:
		print("WARNING: Possible password sprayng detected!")
		print(spray_alerts)
	
	alerts = generate_all_alerts(logs)

	saved_count = save_alerts(alerts)

	print(f"\nSaved {saved_count} new alerts to PostgtreSQL.")

	print("\nSecurity Alerts")
	print("---------------")

	for alert in alerts:
		print(
			f'{alert["severity"]} |'
			f'{alert["rule_id"]} |'
			f'{alert["alert_type"]} |'
			f'{alert["source_ip"]} |'
			f'{alert["username"]} |'
		)

if __name__ == "__main__":
	main()	