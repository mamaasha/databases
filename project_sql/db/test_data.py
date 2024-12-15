from db.models import (
    db, User, Category, Slide, Presentation,
    SearchResult, Log, Error, UserRole,
    SlideTypeEnum, LogLevel, ErrorLevel
)
from datetime import datetime, timezone
from app import app

def create_test_data():
    try:
        with app.app_context():
            user_admin = User.query.filter_by(username='admin').first()
            if not user_admin:
                user_admin = User(username='admin', role=UserRole.ADMIN)
                user_admin.set_password('adminpass')
                db.session.add(user_admin)

            user_editor = User.query.filter_by(username='editor').first()
            if not user_editor:
                user_editor = User(username='editor', role=UserRole.EDITOR)
                user_editor.set_password('editorpass')
                db.session.add(user_editor)

            user_regular = User.query.filter_by(username='user').first()
            if not user_regular:
                user_regular = User(username='user', role=UserRole.USER)
                user_regular.set_password('userpass')
                db.session.add(user_regular)

            db.session.commit()

            category_tech = Category.query.filter_by(category_name='Technology').first()
            if not category_tech:
                category_tech = Category(category_name='Technology')
                db.session.add(category_tech)

            category_business = Category.query.filter_by(category_name='Business').first()
            if not category_business:
                category_business = Category(category_name='Business')
                db.session.add(category_business)

            db.session.commit()

            presentation1 = Presentation.query.filter_by(google_slide_id='GSLIDE123456nje4rbur').first()
            if not presentation1:
                presentation1 = Presentation(
                    google_slide_id='GSLIDE123456nje4rbur',
                    name='Tech Innovations',
                    created_by=user_admin.user_id
                )
                db.session.add(presentation1)

            presentation2 = Presentation.query.filter_by(google_slide_id='GSLIDE654321eufh34uhf').first()
            if not presentation2:
                presentation2 = Presentation(
                    google_slide_id='GSLIDE654321eufh34uhf',
                    name='Business Strategies',
                    created_by=user_editor.user_id
                )
                db.session.add(presentation2)

            db.session.commit()

            slide1 = Slide.query.filter_by(presentation_name='Tech Innovations', topic='AI Advancements').first()
            if not slide1:
                slide1 = Slide(
                    presentation_name='Tech Innovations',
                    topic='AI Advancements',
                    industry='Technology',
                    slide_type=SlideTypeEnum.CASE,  
                    added_by=user_admin.user_id,
                    category_id=category_tech.category_id,
                    added_date=datetime.now(timezone.utc)
                )
                db.session.add(slide1)

            slide2 = Slide.query.filter_by(presentation_name='Tech Innovations', topic='Quantum Computing').first()
            if not slide2:
                slide2 = Slide(
                    presentation_name='Tech Innovations',
                    topic='Quantum Computing',
                    industry='Technology',
                    slide_type=SlideTypeEnum.TITLE,  
                    added_by=user_admin.user_id,
                    category_id=category_tech.category_id,
                    added_date=datetime.now(timezone.utc)
                )
                db.session.add(slide2)

            slide3 = Slide.query.filter_by(presentation_name='Business Strategies', topic='Market Analysis').first()
            if not slide3:
                slide3 = Slide(
                    presentation_name='Business Strategies',
                    topic='Market Analysis',
                    industry='Business',
                    slide_type=SlideTypeEnum.OTHER,  
                    added_by=user_editor.user_id,
                    category_id=category_business.category_id,
                    added_date=datetime.now(timezone.utc)
                )
                db.session.add(slide3)

            db.session.commit()

            search_result1 = SearchResult.query.filter_by(search_query='AI').first()
            if not search_result1:
                search_result1 = SearchResult(
                    user_id=user_regular.user_id,
                    search_query='AI',
                    result_slides=[
                        {"slide_id": slide1.slide_id, "title": slide1.topic, "score": 0.95},
                        {"slide_id": slide2.slide_id, "title": slide2.topic, "score": 0.90}
                    ],
                    search_date=datetime.now(timezone.utc),
                    duration=1.23
                )
                db.session.add(search_result1)

            db.session.commit()

            log1 = Log.query.filter_by(action='create_slide').first()
            if not log1:
                log1 = Log(
                    user_id=user_admin.user_id,
                    action='create_slide',
                    details='Created slide on AI Advancements.',
                    log_level=LogLevel.INFO,
                    log_date=datetime.utcnow()
                )
                db.session.add(log1)

            log2 = Log.query.filter_by(action='update_presentation').first()
            if not log2:
                log2 = Log(
                    user_id=user_editor.user_id,
                    action='update_presentation',
                    details='Updated Business Strategies presentation.',
                    log_level=LogLevel.WARNING,
                    log_date=datetime.utcnow()
                )
                db.session.add(log2)

            db.session.commit()

            error1 = Error.query.filter_by(error_message='Failed to load slide data.').first()
            if not error1:
                error1 = Error(
                    user_id=user_regular.user_id,
                    error_message='Failed to load slide data.',
                    error_level=ErrorLevel.ERROR,
                    error_date=datetime.utcnow()
                )
                db.session.add(error1)

            error2 = Error.query.filter_by(error_message='Database connection timeout.').first()
            if not error2:
                error2 = Error(
                    user_id=user_admin.user_id,
                    error_message='Database connection timeout.',
                    error_level=ErrorLevel.CRITICAL,
                    error_date=datetime.utcnow()
                )
                db.session.add(error2)

            db.session.commit()

            print("Тестовые данные добавлены урааааааа")

    except Exception as e:
        db.session.rollback()
        print(f"Ошибка: {e}")

if __name__ == '__main__':
    with app.app_context():
        create_test_data()
