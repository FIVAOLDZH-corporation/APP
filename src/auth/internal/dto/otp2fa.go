package dto

type Key struct {
	Secret string `json:"secret"`
}

type ValidStatus struct {
	Valid bool `json:"valid"`
}

type EnabledStatus struct {
	Enabled bool `json:"enabled"`
}

type ValidateOTPRequest struct {
	Email string `json:"email"`
	OTP   string `json:"otp"`
}

type LoginOTPRequest struct {
	Email string `json:"email"`
	OTP   string `json:"otp"`
}

type GenerateOTPSecretRequest struct {
	Email string `json:"email"`
}

type Enable2FARequest struct {
	Email string `json:"email"`
}

type Disable2FARequest struct {
	Email string `json:"email"`
}

type Enabled2FARequest struct {
	Email string `json:"email"`
}

type UpdatePassword2FARequest struct {
	Email       string `json:"email"`
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
	OTP         string `json:"otp"`
}
