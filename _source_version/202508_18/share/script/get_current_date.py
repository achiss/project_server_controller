from datetime import datetime, date


def get_current_date() -> date:

    _date: datetime = datetime.now()
    return date(_date.year, _date.month, _date.day)


def get_current_date_string() -> str: return str(get_current_date())
