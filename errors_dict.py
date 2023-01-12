errors = {
    "BadRequestError":"The API request is invalid or malformed. "
                      "The message usually provides details about why the request is not valid.",
    "InvalidArgumentError":"Some of the provided arguments are incorrect.",
    "NotAvailableYet":"The resource is not available yet, but will become available later.",
    "UnselectiveContentQueryError":"Content search query is not selective enough.",
    "UnsupportedContentQueryError":"Unsupported content search query.",
    "AuthenticationRequiredError":"The operation requires an authenticated user. Verify that you have provided your API key.",
    "UserNotActiveError":"The user account is not active. Make sure you properly activated your account by following the link sent to your email.",
    "WrongCredentialsError":"The provided API key is incorrect.",
    "ForbiddenError":"You are not allowed to perform the requested operation.",
    "NotFoundError":"The requested resource was not found.",
    "AlreadyExistsError":"The resource already exists.",
    "FailedDependencyError":"The request depended on another request and that request failed.",
    "QuotaExceededError":"You have exceeded one of your quotas (minute, daily or monthly). "
                         "Daily quotas are reset every day at 00:00 UTC.You may have run out of disk space and/or number "
                         "of files on your VirusTotal Monitor account.",
    "TooManyRequestsError":"Too many requests.",
    "TransientError":"Transient server error. Retry might work.",
    "DeadlineExceededError":"The operation took too long to complete."
    }