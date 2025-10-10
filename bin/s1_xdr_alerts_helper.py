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
BASE_URL_TEMPLATE = "https://{subdomain}.sentinelone.net/web/api/v2.1"



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


def get_account_config(session_key: str, account_name: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Get api_key, subdomain, and scope_id from account configuration.

    Args:
        session_key: Splunk session key
        account_name: Name of the account

    Returns:
        Tuple of (api_key, subdomain, scope_id); each may be None if not found
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
            return None, None, None

        api_key = (account_config.get("api_key") or "").strip()
        subdomain = (account_config.get("subdomain") or "").strip()
        scope_id = (account_config.get("scope_id") or "").strip()
        return api_key or None, subdomain or None, scope_id or None

    except Exception as e:
        # Log the specific error for debugging
        logger = logging.getLogger(__name__)
        logger.error(f"Error retrieving account config for '{account_name}': {e}")
        logger.debug(f"Full exception details: {e}", exc_info=True)
        return None, None, None

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
            return True, checkpoint_data.get("last_cursor")
        else:
            # No checkpoint yet
            return True, None
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
        checkpoint_collection.update(checkpoint_name, {'last_cursor': checkpoint_value})
        return True
    except Exception as e:
        logger.error(f"Error setting checkpoint: {e}")
        return False


def get_sentinelone_alerts_data(
    logger: logging.Logger,
    api_key: str,
    base_url: str,
    last_cursor: Optional[str],
    scope_id: str,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Retrieve SentinelOne alerts (GraphQL) with scope filter and pagination (250/page).

    Args:
        logger: Logger instance
        api_key: SentinelOne API key
        base_url: SentinelOne base URL (e.g., https://<subdomain>.sentinelone.net/web/api/v2.1)
        last_checkpoint: ISO timestamp to use as cutoff (detectedAt)
        scope_ids: scope ID
        scope_type: Scope type string (ACCOUNT/SITE/GROUP)

    Returns:
        Tuple of (events, last_end_cursor)
    """
    try:
        logger.info(f"Starting get_sentinelone_alerts_data with parameters:")
        logger.info(f"  - base_url: {base_url}")
        logger.info(f"  - last_cursor: {last_cursor}")
        logger.info(f"  - scope_id: {scope_id}")
        logger.info(f"  - api_key length: {len(api_key) if api_key else 'None'}")
        
        graphql_url = f"{base_url.rstrip('/')}/unifiedalerts/graphql"
        logger.info(f"GraphQL URL: {graphql_url}")

        # Test basic connectivity first
        headers = {
            "Authorization": f"ApiToken {api_key}",
            "Content-Type": "application/json",
        }
        
        # Simple test query to validate connection
        test_query = """
        query {
            __schema {
                types {
                    name
                }
            }
        }
        """
        
        logger.info("Testing API connectivity with schema query...")
        try:
            test_response = requests.post(graphql_url, json={"query": test_query}, headers=headers, timeout=30)
            logger.info(f"Connectivity test response status: {test_response.status_code}")
            if test_response.status_code == 200:
                logger.info("API connectivity test successful")
            else:
                logger.warning(f"API connectivity test returned status {test_response.status_code}: {test_response.text}")
        except Exception as conn_error:
            logger.error(f"API connectivity test failed: {conn_error}")
            return [], last_cursor

        # Test a simple alerts query without scope filtering to see if there are any alerts at all
        logger.info("Testing basic alerts query without scope filtering...")
        basic_test_query = """
        query {
            alerts(first: 5) {
                pageInfo {
                    hasNextPage
                    endCursor
                }
                edges {
                    cursor
                    node {
                        id
                        name
                        detectedAt
                    }
                }
            }
        }
        """
        
        try:
            basic_response = requests.post(graphql_url, json={"query": basic_test_query}, headers=headers, timeout=30)
            logger.info(f"Basic alerts test response status: {basic_response.status_code}")
            if basic_response.status_code == 200:
                basic_data = basic_response.json()
                if "data" in basic_data and "alerts" in basic_data["data"]:
                    basic_edges = basic_data["data"]["alerts"].get("edges", [])
                    logger.info(f"Basic alerts query returned {len(basic_edges)} alerts (without scope filtering)")
                    if basic_edges:
                        sample_alert = basic_edges[0].get("node", {})
                        logger.info("Sample alert ID: " + sample_alert.get("id", "unknown"))
                        # Try to extract scope information from the alert if available
                        if "asset" in sample_alert and sample_alert["asset"]:
                            asset_info = sample_alert["asset"]
                            logger.info(f"Sample alert asset info: {asset_info}")
                else:
                    logger.warning("Basic alerts query returned unexpected structure")
            else:
                logger.warning(f"Basic alerts test failed with status {basic_response.status_code}: {basic_response.text}")
        except Exception as basic_error:
            logger.error(f"Basic alerts test failed: {basic_error}")

        # Test alerts query with scope filtering to see if scope is the issue
        logger.info("Testing alerts query with scope filtering...")
        scope_test_query = f"""
        query {{
            alerts(
                first: 5,
                scope: {{ scopeIds: "{scope_id.strip()}", scopeType: ACCOUNT }}
            ) {{
                pageInfo {{
                    hasNextPage
                    endCursor
                }}
                edges {{
                    cursor
                    node {{
                        id
                        name
                        detectedAt
                    }}
                }}
            }}
        }}
        """
        
        try:
            scope_response = requests.post(graphql_url, json={"query": scope_test_query}, headers=headers, timeout=30)
            logger.info(f"Scope-filtered alerts test response status: {scope_response.status_code}")
            if scope_response.status_code == 200:
                scope_data = scope_response.json()
                if "data" in scope_data and "alerts" in scope_data["data"]:
                    scope_edges = scope_data["data"]["alerts"].get("edges", [])
                    logger.info(f"Scope-filtered alerts query returned {len(scope_edges)} alerts")
                    if scope_edges:
                        logger.info("Sample scoped alert ID: " + scope_edges[0].get("node", {}).get("id", "unknown"))
                    else:
                        logger.warning(f"No alerts found with scope ID: {scope_id}")
                else:
                    logger.warning("Scope-filtered alerts query returned unexpected structure")
            else:
                logger.warning(f"Scope-filtered alerts test failed with status {scope_response.status_code}: {scope_response.text}")
        except Exception as scope_error:
            logger.error(f"Scope-filtered alerts test failed: {scope_error}")

        # Test with the working scope ID from the user's example
        working_scope_id = "2096563114924818107"
        if working_scope_id != scope_id:
            logger.info(f"Testing with the working scope ID: {working_scope_id}")
            working_scope_test_query = f"""
            query {{
                alerts(
                    first: 5,
                    scope: {{ scopeIds: "{working_scope_id}", scopeType: ACCOUNT }}
                ) {{
                    pageInfo {{
                        hasNextPage
                        endCursor
                    }}
                    edges {{
                        cursor
                        node {{
                            id
                            name
                            detectedAt
                        }}
                    }}
                }}
            }}
            """
            
            try:
                working_scope_response = requests.post(graphql_url, json={"query": working_scope_test_query}, headers=headers, timeout=30)
                logger.info(f"Working scope test response status: {working_scope_response.status_code}")
                if working_scope_response.status_code == 200:
                    working_scope_data = working_scope_response.json()
                    if "data" in working_scope_data and "alerts" in working_scope_data["data"]:
                        working_scope_edges = working_scope_data["data"]["alerts"].get("edges", [])
                        logger.info(f"Working scope ID query returned {len(working_scope_edges)} alerts")
                        if working_scope_edges:
                            logger.info("Sample working scope alert ID: " + working_scope_edges[0].get("node", {}).get("id", "unknown"))
                        else:
                            logger.warning(f"No alerts found even with working scope ID: {working_scope_id}")
                    else:
                        logger.warning("Working scope query returned unexpected structure")
                else:
                    logger.warning(f"Working scope test failed with status {working_scope_response.status_code}: {working_scope_response.text}")
            except Exception as working_scope_error:
                logger.error(f"Working scope test failed: {working_scope_error}")

        # Test if cursor is causing issues by testing without cursor
        if last_cursor:
            logger.info(f"Testing alerts query with scope but WITHOUT cursor (last_cursor was: {last_cursor})...")
            no_cursor_test_query = f"""
            query {{
                alerts(
                    first: 5,
                    scope: {{ scopeIds: "{scope_id.strip()}", scopeType: ACCOUNT }},
                    sort: {{ order: DESC, by: "detectedAt" }}
                ) {{
                    pageInfo {{
                        hasNextPage
                        endCursor
                    }}
                    edges {{
                        cursor
                        node {{
                            id
                            name
                            detectedAt
                        }}
                    }}
                }}
            }}
            """
            
            try:
                no_cursor_response = requests.post(graphql_url, json={"query": no_cursor_test_query}, headers=headers, timeout=30)
                logger.info(f"No-cursor alerts test response status: {no_cursor_response.status_code}")
                if no_cursor_response.status_code == 200:
                    no_cursor_data = no_cursor_response.json()
                    if "data" in no_cursor_data and "alerts" in no_cursor_data["data"]:
                        no_cursor_edges = no_cursor_data["data"]["alerts"].get("edges", [])
                        logger.info(f"No-cursor alerts query returned {len(no_cursor_edges)} alerts")
                        if no_cursor_edges:
                            logger.info("Sample no-cursor alert ID: " + no_cursor_edges[0].get("node", {}).get("id", "unknown"))
                        else:
                            logger.warning(f"No alerts found even without cursor filtering")
                    else:
                        logger.warning("No-cursor alerts query returned unexpected structure")
                else:
                    logger.warning(f"No-cursor alerts test failed with status {no_cursor_response.status_code}: {no_cursor_response.text}")
            except Exception as no_cursor_error:
                logger.error(f"No-cursor alerts test failed: {no_cursor_error}")

        def format_scope_id(sid: str) -> str:
            return f'"{sid.strip()}"'

        def build_query(after_cursor: Optional[str] = None) -> str:
            params = [
                f"scope: {{ scopeIds: {format_scope_id(scope_id)}, scopeType: ACCOUNT }}",
                "viewType: ALL",
                'sort: { order: DESC, by: "detectedAt" }',
                "first: 250",
            ]
            if after_cursor:
                params.append(f'after: "{after_cursor}"')
            
            logger.debug(f"Building GraphQL query with params: {params}")
            query = f"""
            query getAlertsList {{
                alerts(
                    {', '.join(params)}
                ) {{
                    pageInfo {{
                        hasNextPage
                        endCursor
                        startCursor
                    }}
                    edges {{
                        cursor
                        node {{
                            id
                            name
                            status
                            detectedAt
                            createdAt
                            analytics {{
                                category
                                name
                                type
                                typeValue
                                uid
                            }}
                            analystVerdict
                            asset {{
                                agentUuid
                                agentVersion
                                assetTypeClassifier
                                category
                                connectivityToConsole
                                id
                                lastLoggedInUser
                                name
                                osType
                                osVersion
                                pendingReboot
                                policy
                                subcategory
                                type
                            }}
                            classification
                            attackSurfaces
                            confidenceLevel
                            dataSources
                            description
                            detectionSource {{
                                engine
                                product
                                vendor
                            }}
                            detectionTime {{
                                cloud {{
                                    accountId
                                    cloudProvider
                                    image
                                    instanceId
                                    instanceSize
                                    location
                                    network
                                    providerDetails {{
                                        ... on DetectionAws {{
                                            accountId
                                            imageId
                                            instanceId
                                            instanceType
                                            region
                                            role
                                            securityGroups
                                            subnetIds
                                            tags
                                            vpcId
                                        }}
                                        ... on DetectionGcp {{
                                            imageId
                                            instanceId
                                            instanceType
                                            projectId
                                            serviceAccount
                                            tags
                                            vpcId
                                            zone
                                        }}
                                        ... on DetectionAzure {{
                                            imageId
                                            instanceId
                                            instanceType
                                            region
                                            resourceGroup
                                            subscriptionId
                                            tags
                                        }}
                                    }}
                                    tags
                                }}
                                attacker {{
                                    host
                                    ip
                                }}
                                asset {{
                                    ipV4
                                    ipV6
                                    lastLoggedInUser
                                }}
                                targetUser {{
                                    domain
                                    emailAddress
                                    name
                                }}
                                kubernetes {{
                                    clusterName
                                    containerId
                                    containerImageName
                                    containerLabels
                                    containerName
                                    containerNetworkStatus
                                    controllerLabels
                                    controllerName
                                    controllerType
                                    namespaceLabels
                                    namespaceName
                                    nodeLabels
                                    nodeName
                                    podLabels
                                    podName
                                }}
                            }}
                            fileHash
                            fileName
                            firstSeenAt
                            lastSeenAt
                            process {{
                                cmdLine
                                parentName
                                file {{
                                    certSubject
                                    md5
                                    name
                                    path
                                    sha1
                                    sha256
                                }}
                            }}
                            result
                            severity
                            storylineId
                            updatedAt
                        }}
                    }}
                }}
            }}
            """
            logger.debug(f"Generated GraphQL query: {query}")
            return query

        logger.debug(f"Request headers: {dict(headers)}")

        all_alerts: List[Dict[str, Any]] = []
        after_cursor: Optional[str] = last_cursor
        page_count = 0
        should_continue = True
        last_end_cursor: Optional[str] = last_cursor

        while should_continue:
            page_count += 1

            query = build_query(after_cursor)
            payload = {"query": query}

            logger.info(f"Requesting alerts page {page_count} from: {graphql_url}")
            logger.debug(f"Request payload: {payload}")

            # Request with retry/backoff and rate-limit handling
            max_retries = 5
            attempt = 0
            response = None
            logger.debug(f"Starting request loop with max_retries={max_retries}")
            while attempt < max_retries:
                attempt += 1
                logger.debug(f"Making request attempt {attempt}/{max_retries}")
                try:
                    response = requests.post(graphql_url, json=payload, headers=headers, timeout=60)
                    logger.debug(f"Received response with status code: {response.status_code}")

                    # Log rate-limit headers if present
                    try:
                        remaining = response.headers.get("X-RateLimit-Remaining") or response.headers.get("x-ratelimit-remaining")
                        if remaining is not None:
                            logger.debug(f"RateLimit remaining: {remaining}")
                    except Exception:
                        pass

                    if response.status_code == 429:
                        retry_after = response.headers.get("Retry-After") or response.headers.get("retry-after")
                        if retry_after is not None:
                            try:
                                wait_s = int(retry_after)
                            except Exception:
                                wait_s = min(2 ** attempt, 60)
                        else:
                            wait_s = min(2 ** attempt, 60)
                        logger.warning(f"HTTP 429 Too Many Requests. Waiting {wait_s}s before retry #{attempt}")
                        time.sleep(wait_s)
                        continue

                    if 500 <= response.status_code < 600:
                        wait_s = min(2 ** attempt, 60)
                        logger.warning(f"Server error {response.status_code}. Retrying in {wait_s}s (attempt {attempt}/{max_retries})")
                        time.sleep(wait_s)
                        continue

                    # Non-retry or success path
                    break

                except requests.exceptions.RequestException as e:
                    if attempt >= max_retries:
                        logger.error(f"Network error after {attempt} attempts: {e}")
                        response = None
                        break
                    wait_s = min(2 ** attempt, 30)
                    logger.warning(f"Request attempt {attempt} failed: {e}. Retrying in {wait_s}s")
                    time.sleep(wait_s)

            if response is None:
                logger.error("Aborting due to repeated request failures")
                break

            if response.status_code != 200:
                logger.error(f"GraphQL API request failed with status code: {response.status_code}")
                logger.error(f"Response: {response.text}")
                break

            logger.debug(f"Processing successful response (status 200)")
            try:
                data = response.json()
                logger.debug(f"Successfully parsed JSON response")
            except Exception as json_error:
                logger.error(f"Failed to parse JSON response: {json_error}")
                logger.error(f"Response text: {response.text}")
                break
                
            if "errors" in data:
                errs = data.get('errors', [])
                # If errors indicate rate limiting, backoff once and retry page
                rate_limited = any('rate' in (err.get('message', '').lower()) and 'limit' in (err.get('message', '').lower()) for err in errs)
                if rate_limited:
                    logger.warning("GraphQL error indicates rate limiting; backing off 5s and retrying page")
                    time.sleep(5)
                    # Do not advance cursor, retry the same page once
                    continue
                logger.error(f"GraphQL errors: {errs}")
                break

            alerts_container = data.get("data", {}).get("alerts", {})
            logger.debug(f"Alerts container keys: {list(alerts_container.keys())}")
            
            edges = alerts_container.get("edges", [])
            page_info = alerts_container.get("pageInfo", {})
            logger.debug(f"Found {len(edges)} edges, pageInfo: {page_info}")

            if not edges:
                logger.info("No more alerts returned from API")
                # If this is the first page and we have a cursor but got no results,
                # it might mean the cursor is pointing to a position beyond available data
                if page_count == 1 and after_cursor:
                    logger.warning(f"First page returned no results with cursor {after_cursor}. This might indicate cursor is beyond available data.")
                break

            page_alerts: List[Dict[str, Any]] = [edge.get("node", {}) for edge in edges if edge.get("node")]
            logger.debug(f"Extracted {len(page_alerts)} alerts from edges")

            if page_alerts:
                all_alerts.extend(page_alerts)
                logger.info(f"Fetched {len(page_alerts)} alerts on page {page_count} (total: {len(all_alerts)})")

            last_end_cursor = page_info.get("endCursor")
            has_next_page = page_info.get("hasNextPage", False)
            logger.debug(f"Page info - endCursor: {last_end_cursor}, hasNextPage: {has_next_page}")
            
            if not has_next_page:
                logger.info("Reached last page from API")
                break

            after_cursor = last_end_cursor

        logger.info(f"Retrieved {len(all_alerts)} alerts from SentinelOne")
        return all_alerts, last_end_cursor

    except Exception as e:
        logger.error(f"Exception while retrieving alerts from SentinelOne: {e}")
        logger.debug(f"Full exception details: {e}", exc_info=True)
        return [], last_cursor


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

            logger.debug(f"Retrieving account config for account: {account_name}")
            api_key, subdomain, account_scope_id = get_account_config(session_key, account_name)
            if not api_key:
                logger.error(f"No API key found for account: {account_name}")
                continue
            if not subdomain:
                logger.error("Missing required account 'subdomain' in ta_sentinelone_xdr_account.conf")
                continue
            base_url = BASE_URL_TEMPLATE.format(subdomain=subdomain)

            # Log credential validation (without exposing actual values)
            logger.debug(f"API key retrieved - length: {len(api_key)}")

            # Basic validation of API key format
            if not api_key.strip():
                logger.error(f"Invalid API key for account {account_name}: key contains only whitespace")
                continue

            # Handle checkpointing
            checkpoint_name = f"{account_name}-{normalized_input_name}-alerts".replace("://", "_")
            checkpoint_valid, last_cursor = get_checkpoint(logger, session_key, checkpoint_name)

            if not checkpoint_valid:
                logger.error("Failed to retrieve checkpoint data")
                continue

            current_run_time = datetime.utcnow().isoformat() + "Z"
            logger.info(f"Last cursor: {last_cursor}, Current run time: {current_run_time}")

            # Obtain scope_id from account configuration
            if not account_scope_id:
                logger.error("Missing required account 'scope_id' in ta_sentinelone_xdr_account.conf")
                continue
            if "," in account_scope_id:
                logger.error("Multiple scope IDs provided in account; only one 'scope_id' is supported")
                continue
            if account_scope_id.startswith("[") and account_scope_id.endswith("]"):
                logger.error("List provided in account 'scope_id'; only a single ID string is supported")
                continue
            scope_id: str = account_scope_id.strip().strip("'\"")

            # Get alerts data from SentinelOne
            logger.info("Starting SentinelOne alert collection")
            logger.info(f"Collection parameters - Account: {account_name}, URL: {base_url}, ScopeType: ACCOUNT, ScopeId: {scope_id}")

            collection_start_time = time.time()
            logger.info("Calling get_sentinelone_alerts_data function...")
            alert_events, new_last_cursor = get_sentinelone_alerts_data(
                logger=logger,
                api_key=api_key,
                base_url=base_url,
                last_cursor=last_cursor,
                scope_id=scope_id,
            )
            collection_duration = time.time() - collection_start_time

            logger.info(f"Alert collection completed in {collection_duration:.2f} seconds")
            logger.info(f"Returned {len(alert_events) if alert_events else 0} alert events")
            logger.info(f"New cursor: {new_last_cursor}")

            if not alert_events:
                logger.warning("No alert events generated")
                # If we have a cursor but got no results, the cursor might be stale
                # Let's try resetting the cursor and running again
                if last_cursor:
                    logger.info("Attempting to reset cursor and retry collection...")
                    reset_start_time = time.time()
                    alert_events_reset, new_last_cursor_reset = get_sentinelone_alerts_data(
                        logger=logger,
                        api_key=api_key,
                        base_url=base_url,
                        last_cursor=None,  # Reset cursor to None
                        scope_id=scope_id,
                    )
                    reset_duration = time.time() - reset_start_time
                    logger.info(f"Reset cursor collection completed in {reset_duration:.2f} seconds")
                    logger.info(f"Reset attempt returned {len(alert_events_reset) if alert_events_reset else 0} alert events")
                    
                    if alert_events_reset:
                        logger.info("Successfully retrieved alerts after cursor reset")
                        alert_events = alert_events_reset
                        new_last_cursor = new_last_cursor_reset
                    else:
                        logger.warning("Still no alerts after cursor reset - there may genuinely be no alerts")
                        continue
                else:
                    logger.warning("No cursor was set, so no reset attempt needed")
                    continue

            # Update cursor-based checkpoint
            if new_last_cursor:
                if set_checkpoint(logger, session_key, checkpoint_name, new_last_cursor):
                    logger.info(f"Successfully updated cursor checkpoint to: {new_last_cursor}")
                else:
                    logger.warning("Failed to update cursor checkpoint")

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

                # Checkpoint already updated above using cursor

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
