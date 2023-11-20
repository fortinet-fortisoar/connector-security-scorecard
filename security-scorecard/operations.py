""""
Copyright start
MIT License
Copyright (c) 2023 Fortinet Inc
Copyright end
"""

import requests
from connectors.core.connector import get_logger, ConnectorError
logger = get_logger('security-scorecard')


class SecurityScorecard(object):

    def __init__(self, config):
        self.server_url = config.get('server_url').strip()
        self.api_key = config.get('api_key')
        self.headers = {'accept': 'application/json', 'Authorization': 'Token '+self.api_key}
        if not self.server_url.startswith('https://') and not self.server_url.startswith('http://'):
            self.server_url = 'https://{0}/'.format(self.server_url)

    def make_api_call(self, endpoint=None, method='GET', headers=None, health_check=False):
        url = self.server_url + endpoint
        logger.debug('API Service URL: {0}'.format(url))
        if headers:
            self.headers.update(headers)
        try:
            logger.debug('Making a request with {0} method and {1} headers.'.format(method, self.headers))
            response = requests.request(method, url, headers=self.headers)
            if response.status_code in [200]:
                if health_check:
                    return response
                try:
                    logger.debug(
                        'Converting the response into JSON format after returning with status code: {0}'.format(
                            response.status_code))
                    response_data = response.json()
                    return {'status': response_data['status'] if 'status' in response_data else 'Success',
                            'data': response_data}
                except Exception as e:
                    response_data = response.content
                    logger.error('Failed with an error: {0}. The response details are: {1}'.format(e, response_data))
                    return {'status': 'Failure', 'data': response_data}
            else:
                logger.error('Failed with response {0}'.format(response))
                raise ConnectorError(
                    {'status': 'Failure', 'status_code': str(response.status_code), 'response': response})
        except Exception as e:
            logger.exception(str(e))
            raise ConnectorError(str(e))


def get_all_companies_portfolio(config, params):
    """
        Retrieves a list companies of from security scorecard.
        :param config: config
        :param params: params
        :return: List of all details,all companies portfolio from security scorecard.
    """
    obj = SecurityScorecard(config)
    endpoint = '/portfolios/{0}/companies'.format(params.get('portfolio_id'))
    return obj.make_api_call(endpoint=endpoint)


def get_list_of_portfolio(config, params):
    """
           Retrieves a list portfolio of from security scorecard.
           :param config: config
           :param params: params
           :return: List of all details,list portfolio of from security scorecard.
    """
    obj = SecurityScorecard(config)
    endpoint = '/portfolios'
    return obj.make_api_call(endpoint=endpoint)


def get_company_score(config, params):
    """
          Retrieve company overall score from security scorecard.
          :param config: config
          :param params: params
          :return: List of all details,company overall score from security scorecard.
    """
    obj = SecurityScorecard(config)
    endpoint = '/companies/{0}'.format(params.get('domain'))
    return obj.make_api_call(endpoint=endpoint)


def get_company_factor_score(config, params):
    """
         Retrieve company factor score from security scorecard.
         :param config: config
         :param params: params
         :return: List of all details,company factor score from security scorecard.
    """
    obj = SecurityScorecard(config)
    endpoint = '/companies/{0}/factors'.format(params.get('domain'))
    return obj.make_api_call(endpoint=endpoint)


def get_company_history_score(config, params):
    """
        Retrieve company history score from security scorecard.
        :param config: config
        :param params: params
        :return: List of all details,company history score from security scorecard.
    """
    obj = SecurityScorecard(config)
    endpoint = '/companies/{0}/history/score'.format(params.get('domain'))
    return obj.make_api_call(endpoint=endpoint)


def get_company_history_factor_score(config, params):
    """
       Retrieve company history factor score from security scorecard.
        :param config: config
        :param params: params
        :return: List of all details,company history factor score from security scorecard.
    """
    obj = SecurityScorecard(config)
    endpoint = '/companies/{0}/history/factors/score'.format(params.get('domain'))
    return obj.make_api_call(endpoint=endpoint)


def get_alert_list(config, params):
    """
        Retrieve list alerts triggered from security scorecard."
        :param config: config
        :param params: params
        :return: List of all details, alerts triggered from security scorecard.",
    """
    obj = SecurityScorecard(config)
    endpoint = '/users/by-username/{0}/notifications/recent'.format(params.get('email_id'))
    return obj.make_api_call(endpoint=endpoint)


def get_ransomware_details(config, params):
    """
      "Retrieve ransomware details triggered from security scorecard."
       :param config: config
       :param params: params
       :return: List of all details, ransomware details triggered from security scorecard.",
    """
    obj = SecurityScorecard(config)
    endpoint = '/asi/details/ransomware/{0}'.format(params.get('ransomware_id'))
    return obj.make_api_call(endpoint=endpoint)


def _check_health(config):
    try:
        obj = SecurityScorecard(config)
        obj.make_api_call(endpoint='/portfolios', health_check=True)
        return True
    except Exception as err:
        logger.exception('Health check failed with: {0}'.format(err))
        raise ConnectorError('Health check failed with: {0}'.format(err))


operations = {
    'get_all_companies_portfolio': get_all_companies_portfolio,
    'get_list_of_portfolio': get_list_of_portfolio,
    'get_company_score': get_company_score,
    'get_company_factor_score': get_company_factor_score,
    'get_company_history_score': get_company_history_score,
    'get_company_history_factor_score': get_company_history_factor_score,
    'get_alert_list': get_alert_list,
    'get_ransomware_details': get_ransomware_details
}
