package com.greenloop.auth_service.util;

public class EmailTemplateUtil {

    public static String otpVerificationEmail(String otpCode) {
        return """
                    <html>
                        <body style="font-family: Arial, sans-serif; color: #333; background-color: #f9fafb; padding: 20px;">
                            <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); padding: 30px;">
                                <h2 style="text-align: center; color: #1b5e20;">GreenLoop Verification</h2>
                                <p>Hello,</p>
                                <p>Thank you for registering with <b>GreenLoop</b>. Please use the following One-Time Password (OTP) to verify your account:</p>

                                <div style="text-align: center; margin: 30px 0;">
                                    <span style="font-size: 24px; font-weight: bold; background-color: #e8f5e9; color: #2e7d32; padding: 10px 20px; border-radius: 8px;">
                                        %s
                                    </span>
                                </div>

                                <p>This code is valid for <b>5 minutes</b> and can only be used once.</p>
                                <p>If you did not request this code, please ignore this email.</p>

                                <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                                <p style="font-size: 14px; text-align: center; color: #777;">Regards,<br><b>The GreenLoop Team</b></p>
                            </div>
                        </body>
                    </html>
                """
                .formatted(otpCode);
    }
}
