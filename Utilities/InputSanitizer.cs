using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace Secure.Utilities
{
    /// <summary>
    /// Input sanitization and validation utility to prevent XSS and injection attacks
    /// </summary>
    public static class InputSanitizer
    {
        // Dangerous patterns that could indicate XSS or SQL injection attempts
        private static readonly Regex ScriptTagPattern = new Regex(@"<script[^>]*>.*?</script>", 
            RegexOptions.IgnoreCase | RegexOptions.Compiled);
        
        private static readonly Regex HtmlTagPattern = new Regex(@"<[^>]+>", 
            RegexOptions.Compiled);
        
        private static readonly Regex SqlInjectionPattern = new Regex(
            @"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|DECLARE)\b)|(')|(--)|(;)|(/\*)|(\*/)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex JavaScriptEventPattern = new Regex(
            @"(on\w+\s*=)|javascript:",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        /// <summary>
        /// Sanitizes input to prevent XSS attacks by encoding HTML entities
        /// </summary>
        /// <param name="input">Raw user input</param>
        /// <returns>HTML-encoded safe string</returns>
        public static string SanitizeForXss(string? input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return string.Empty;

            // HTML encode to prevent XSS
            string encoded = HttpUtility.HtmlEncode(input);

            // Additional validation: Remove any remaining script tags
            encoded = ScriptTagPattern.Replace(encoded, string.Empty);

            // Remove JavaScript event handlers
            encoded = JavaScriptEventPattern.Replace(encoded, string.Empty);

            return encoded.Trim();
        }

        /// <summary>
        /// Validates username format to prevent malicious input
        /// Only allows alphanumeric characters and underscores
        /// </summary>
        /// <param name="username">Username to validate</param>
        /// <returns>True if valid, false otherwise</returns>
        public static bool IsValidUsername(string? username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;

            // Only allow alphanumeric and underscores, 3-50 characters
            var usernamePattern = new Regex(@"^[a-zA-Z0-9_]{3,50}$");
            return usernamePattern.IsMatch(username);
        }

        /// <summary>
        /// Validates email format to prevent injection attacks
        /// </summary>
        /// <param name="email">Email to validate</param>
        /// <returns>True if valid email format, false otherwise</returns>
        public static bool IsValidEmail(string? email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            // RFC 5322 compliant email validation
            var emailPattern = new Regex(
                @"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
                RegexOptions.Compiled);

            return emailPattern.IsMatch(email) && email.Length <= 100;
        }

        /// <summary>
        /// Detects potential SQL injection attempts
        /// Note: This is a defense-in-depth measure. Primary protection is parameterized queries.
        /// </summary>
        /// <param name="input">Input to check</param>
        /// <returns>True if suspicious patterns detected, false otherwise</returns>
        public static bool ContainsSqlInjectionPatterns(string? input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            return SqlInjectionPattern.IsMatch(input);
        }

        /// <summary>
        /// Detects potential XSS attack patterns
        /// </summary>
        /// <param name="input">Input to check</param>
        /// <returns>True if suspicious patterns detected, false otherwise</returns>
        public static bool ContainsXssPatterns(string? input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            return ScriptTagPattern.IsMatch(input) || 
                   JavaScriptEventPattern.IsMatch(input) ||
                   HtmlTagPattern.IsMatch(input);
        }

        /// <summary>
        /// Comprehensive input validation combining multiple security checks
        /// </summary>
        /// <param name="input">Input to validate</param>
        /// <param name="maxLength">Maximum allowed length</param>
        /// <returns>True if input passes all security checks, false otherwise</returns>
        public static bool IsSecureInput(string? input, int maxLength = 100)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            if (input.Length > maxLength)
                return false;

            // Check for malicious patterns
            if (ContainsSqlInjectionPatterns(input) || ContainsXssPatterns(input))
                return false;

            return true;
        }

        /// <summary>
        /// Strips all HTML tags from input
        /// </summary>
        /// <param name="input">Input containing HTML</param>
        /// <returns>Plain text without HTML tags</returns>
        public static string StripHtmlTags(string? input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return string.Empty;

            return HtmlTagPattern.Replace(input, string.Empty).Trim();
        }
    }
}
