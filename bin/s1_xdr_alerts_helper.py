import json
import logging
import time
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple

import import_declare_test
import requests
from solnlib import conf_manager, log
from solnlib.modular_input import checkpointer
from splunklib import modularinput as smi

ADDON_NAME = "ta_sentinelone_xdr"
CHECKPOINTER_NAME = "ta_sentinelone_xdr_checkpoints"
BASE_URL = "https://domain.sentinelone.net/web/api/v2.1"



def logger_for_input(session_key: str, input_name: str) -> logging.Logger:
    """Set up a logger instance for the input.

    Logs are stored in $SPLUNK_HOME/var/log/splunk/ta_sentinelone_xdr_*.log
    The log level is hardcoded to INFO
    """
    # Set up the log directory to ensure logs go to the right place
    try:
        log_dir = os.path.join(os.environ.get('SPLUNK_HOME', ''), 'var', 'log', 'splunk')
        log.Logs.set_context(directory=log_dir, namespace=ADDON_NAME.lower())
    except Exception:
        # If we can't set the context, the solnlib will try to use the default location
        pass

    # Create a safe name for the logger
    safe_input_name = input_name.replace(" ", "_").replace(":", "_").replace("/", "_").replace("\\", "_")
    logger_name = f"{safe_input_name}"

    # Get the logger and hardcode the log level to INFO
    logger = log.Logs().get_logger(logger_name)
    logger.setLevel(logging.INFO)

    return logger


def get_account_api_key(session_key: str, account_name: str) -> Optional[str]:
    """Get API key from account configuration.

    Args:
        session_key: Splunk session key
        account_name: Name of the account

    Returns:
        API key string or None if not found
    """
    try:
        cfm = conf_manager.ConfManager(
            session_key,
            ADDON_NAME,
            realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-ta_sentinelone_xdr_account",
        )
        account_conf_file = cfm.get_conf("ta_sentinelone_xdr_account")
        account_config = account_conf_file.get(account_name)

        if not account_config:
            return None

        # Get the API key
        api_key = account_config.get("api_key")
        return api_key

    except Exception as e:
        # Log the specific error for debugging
        logger = logging.getLogger(__name__)
        logger.error(f"Error retrieving API key for account '{account_name}': {e}")
        logger.debug(f"Full exception details: {e}", exc_info=True)
        return None


def get_checkpoint(logger: logging.Logger, session_key: str, checkpoint_name: str) -> Tuple[bool, Optional[str]]:
    """
    Get checkpoint data from KVStore

    Args:
        logger: Logger instance
        session_key: Splunk session key
        checkpoint_name: Name of the checkpoint

    Returns:
        Tuple of (success, checkpoint_value)
    """
    try:
        checkpoint_collection = checkpointer.KVStoreCheckpointer(
            checkpoint_name, session_key, ADDON_NAME
        )
        checkpoint_data = checkpoint_collection.get(checkpoint_name)
        if checkpoint_data:
            return True, checkpoint_data.get("updated_timestamp")
        else:
            # Default to 90 days ago if no checkpoint exists
            default_time = (datetime.utcnow() - timedelta(days=90)).isoformat() + "Z"
            return True, default_time
    except Exception as e:
        logger.error(f"Error retrieving checkpoint: {e}")
        return False, None


def set_checkpoint(logger: logging.Logger, session_key: str, checkpoint_name: str, checkpoint_value: str) -> bool:
    """
    Set checkpoint data in KVStore

    Args:
        logger: Logger instance
        session_key: Splunk session key
        checkpoint_name: Name of the checkpoint
        checkpoint_value: Value to store

    Returns:
        Success status
    """
    try:
        checkpoint_collection = checkpointer.KVStoreCheckpointer(
            checkpoint_name, session_key, ADDON_NAME
        )
        checkpoint_collection.update(checkpoint_name, {'updated_timestamp': checkpoint_value})
        return True
    except Exception as e:
        logger.error(f"Error setting checkpoint: {e}")
        return False


def get_sentinelone_alerts_data(logger: logging.Logger, api_key: str, base_url: str, last_checkpoint: str) -> List[Dict[str, Any]]:
    """
    Retrieve SentinelOne alerts data using GraphQL API

    Args:
        logger: Logger instance
        api_key: SentinelOne API key
        base_url: SentinelOne base URL
        last_checkpoint: Last checkpoint timestamp

    Returns:
        List of alert events for Splunk
    """
    try:
        # Construct the GraphQL endpoint URL
        graphql_url = f"{base_url.rstrip('/')}/unifiedalerts/graphql"

        # GraphQL query for unified alerts with timestamp filtering
        # Note: This is a representative query - the actual schema may vary
        query = """
        query GetUnifiedAlerts($updatedAt: DateTime) {
          unifiedAlerts(updatedAt: {gte: $updatedAt}) {
            edges {
              node {
                id
                createdAt
                updatedAt
                alertInfo {
                  alertId
                  alertType
                  severity
                  title
                  description
                }
                source {
                  id
                  type
                  name
                }
                agent {
                  id
                  name
                  os
                  version
                }
                threatInfo {
                  threatId
                  classification
                  confidence
                }
                ruleInfo {
                  id
                  name
                  description
                }
              }
            }
          }
        }
        """

        # Variables for the query
        variables = {
            "updatedAt": last_checkpoint
        }

        # Prepare the request payload
        payload = {
            "query": query,
            "variables": variables
        }

        # Set up headers
        headers = {
            "Authorization": f"ApiToken {api_key}",
            "Content-Type": "application/json"
        }

        logger.info(f"Making GraphQL request to: {graphql_url}")
        logger.debug(f"Query variables: {variables}")

        # Make the request
        response = requests.post(graphql_url, json=payload, headers=headers, timeout=60)

        if response.status_code != 200:
            logger.error(f"GraphQL API request failed with status code: {response.status_code}")
            logger.error(f"Response: {response.text}")
            return []

        # Parse the response
        response_data = response.json()

        # Check for GraphQL errors
        if 'errors' in response_data:
            logger.error(f"GraphQL errors: {response_data['errors']}")
            return []

        # Extract alerts from the response
        alerts_data = response_data.get('data', {}).get('unifiedAlerts', {}).get('edges', [])

        alert_events = []
        for edge in alerts_data:
            alert = edge.get('node', {})
            if alert:
                alert_events.append(alert)

        logger.info(f"Retrieved {len(alert_events)} alerts from SentinelOne")
        return alert_events

    except Exception as e:
        logger.error(f"Exception while retrieving alerts from SentinelOne: {e}")
        logger.debug(f"Full exception details: {e}", exc_info=True)
        return []


def validate_input(definition: smi.ValidationDefinition):
    return


def stream_events(inputs: smi.InputDefinition, event_writer: smi.EventWriter):
    """
    Stream SentinelOne alert data to Splunk

    This function retrieves alerts from SentinelOne using GraphQL API
    """
    for input_name, input_item in inputs.inputs.items():
        normalized_input_name = input_name.split("/")[-1]
        session_key = inputs.metadata["session_key"]
        logger = logger_for_input(session_key, normalized_input_name)

        try:
            # Configure logging (hardcoded to INFO in logger_for_input)
            log.modular_input_start(logger, normalized_input_name)

            # Get account configuration
            account_name = input_item.get("account")
            if not account_name:
                logger.error("No account specified in input configuration")
                continue

            logger.debug(f"Retrieving API key for account: {account_name}")
            api_key = get_account_api_key(session_key, account_name)
            if not api_key:
                logger.error(f"No API key found for account: {account_name}")
                continue

            # Use the hardcoded base URL
            base_url = BASE_URL

            # Log credential validation (without exposing actual values)
            logger.debug(f"API key retrieved - length: {len(api_key)}")

            # Basic validation of API key format
            if not api_key.strip():
                logger.error(f"Invalid API key for account {account_name}: key contains only whitespace")
                continue

            # Handle checkpointing
            checkpoint_name = f"{account_name}-{normalized_input_name}-alerts".replace("://", "_")
            checkpoint_valid, last_checkpoint = get_checkpoint(logger, session_key, checkpoint_name)

            if not checkpoint_valid:
                logger.error("Failed to retrieve checkpoint data")
                continue

            current_run_time = datetime.utcnow().isoformat() + "Z"
            logger.info(f"Last checkpoint: {last_checkpoint}, Current run time: {current_run_time}")

            # Get alerts data from SentinelOne
            logger.info("Starting SentinelOne alert collection")
            logger.info(f"Collection parameters - Account: {account_name}, URL: {base_url}")

            collection_start_time = time.time()
            alert_events = get_sentinelone_alerts_data(
                logger=logger,
                api_key=api_key,
                base_url=base_url,
                last_checkpoint=last_checkpoint
            )
            collection_duration = time.time() - collection_start_time

            logger.info(f"Alert collection completed in {collection_duration:.2f} seconds")

            if not alert_events:
                logger.warning("No alert events generated")
                continue

            # Find latest timestamp for checkpoint
            latest_timestamp = last_checkpoint
            for event in alert_events:
                # Update checkpoint if this event has a newer timestamp
                event_timestamp = event.get('updatedAt', event.get('updated_timestamp', ''))
                if event_timestamp and event_timestamp > latest_timestamp:
                    latest_timestamp = event_timestamp

            # Send events to Splunk
            sourcetype = "sentinelone:unified:alert:json"
            index = input_item.get("index", "default")

            try:
                logger.info(f"Sending {len(alert_events)} alert events to Splunk")
                logger.debug(f"Event destination - Index: {index}, Sourcetype: {sourcetype}")

                send_start_time = time.time()

                # Send events individually to maintain proper event boundaries
                events_sent = 0
                for event in alert_events:
                    event_writer.write_event(
                        smi.Event(
                            data=json.dumps(event, ensure_ascii=False, default=str),
                            index=index,
                            sourcetype=sourcetype,
                        )
                    )
                    events_sent += 1

                    # Log progress for large batches
                    if events_sent % 100 == 0:
                        logger.debug(f"Sent {events_sent}/{len(alert_events)} events to Splunk")

                send_duration = time.time() - send_start_time
                logger.info(f"Successfully sent {len(alert_events)} alert events to Splunk in {send_duration:.2f} seconds")

                # Update checkpoint after successful event processing
                if set_checkpoint(logger, session_key, checkpoint_name, latest_timestamp):
                    logger.info(f"Successfully updated checkpoint to: {latest_timestamp}")
                else:
                    logger.warning("Failed to update checkpoint")

                # Log ingestion details
                log.events_ingested(
                    logger,
                    input_name,
                    sourcetype,
                    len(alert_events),
                    index,
                    account=account_name,
                )

            except Exception as send_error:
                logger.error(f"Failed to send events to Splunk: {send_error}")
                logger.debug(f"Send error details: {send_error}", exc_info=True)

            log.modular_input_end(logger, normalized_input_name)

        except Exception as e:
            logger.error(f"Exception in alert collection for {normalized_input_name}: {e}")
            logger.error(f"Exception type: {type(e).__name__}")
            logger.debug(f"Full exception details for {normalized_input_name}: {e}", exc_info=True)
