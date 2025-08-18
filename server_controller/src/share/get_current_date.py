from datetime import datetime, date


def get_current_date() -> date:

    _data: datetime = datetime.now()
    return date(_data.year, _data.month, _data.day)
