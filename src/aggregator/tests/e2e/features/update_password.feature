Feature: User password update

  Scenario: Successful password update
    Given a user "user@gmail.com" with password "user" and 2FA enabled
    When the user sends request to "/2fa/update_password" with passwords and valid OTP
    Then the user receives no error
