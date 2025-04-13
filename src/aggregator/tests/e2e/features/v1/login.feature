Feature: User authentication

  Scenario: Successful login without 2FA
    Given a user "user@gmail.com" with password "user" and 2FA disabled
    When the user sends request to "/login" with password "user"
    Then the user receives an access token

  Scenario: Successful login with 2FA enabled
    Given a user "user@gmail.com" with password "user" and 2FA enabled
    When the user sends request to "/2fa/login" with valid OTP
    Then the user receives an access token

  Scenario: Failed login due to 2FA enabled 
    Given a user "user@gmail.com" with password "user" and 2FA enabled
    When the user sends request to "/login" with password "user"
    Then the response on /login should match json:
        """
        {
            "2fa_required": true
        }
        """
    And the login attempt is rejected

  Scenario: Failed login due to wrong OTP
    Given a user "user@gmail.com" with password "user" and 2FA enabled
    When the user sends request to "/2fa/login" with OTP "000000"
    Then the login attempt is rejected
