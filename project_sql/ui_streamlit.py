import streamlit as st
import requests
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

BACKEND_URL = os.getenv('BACKEND_URL', 'http://127.0.0.1:5000')

def make_request(url, method='GET', data=None, headers=None, expect_json=True):
    try:
        # st.write(f"URL: {url}")
        # st.write(f"Method: {method}")
        # st.write(f"Headers: {headers}")
        # st.write(f"Data: {data}")
        if method == 'GET':
            response = requests.get(url, headers=headers)
        elif method == 'POST':
            response = requests.post(url, json=data, headers=headers)
        elif method == 'PUT':
            response = requests.put(url, json=data, headers=headers)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers)
        response.raise_for_status()
        if expect_json:
            return response.json() if response.content else None
        else:
            return response.content
    except requests.exceptions.HTTPError as http_err:
        st.error(f"HTTP ошибка: {http_err}")
        if http_err.response is not None:
            st.error(f"Статус код: {http_err.response.status_code}")
            st.error(f"Тело ответа: {http_err.response.text}")
        return None
    except requests.exceptions.RequestException as e:
        st.error(f"Ошибка при выполнении запроса: {e}")
        return None

def authenticate(username, password):
    url = f"{BACKEND_URL}/login"
    data = {"username": username, "password": password}
    result = make_request(url, method='POST', data=data)
    if result and 'access_token' in result:
        token = result['access_token'].replace('\n', '').replace(' ', '')
        st.session_state['access_token'] = token
        user_info = make_request(
            f"{BACKEND_URL}/protected",
            headers={'Authorization': f'Bearer {token}'}
        )
        if user_info and 'logged_in_as' in user_info:
            st.session_state['user_role'] = user_info['logged_in_as']['role']
            st.write(f"Роль пользователя: {st.session_state['user_role']}")  # Временное логирование
        return True
    st.error("Неверные имя пользователя или пароль")
    return False

def check_token_ui():
    st.header("Проверка Токена")
    if st.button("Проверить токен", key="check_token_button"):
        headers = {'Authorization': f'Bearer {st.session_state["access_token"]}'}
        response = make_request(f"{BACKEND_URL}/check_token", method='GET', headers=headers)
        if response:
            st.write(f"Пользователь: {response['user']}")
            st.write(f"Роль: {response['role']}")
        else:
            st.error("Не удалось проверить токен.")

def register(username, password, role):
    url = f"{BACKEND_URL}/register"
    data = {"username": username, "password": password, "role": role}
    result = make_request(url, method='POST', data=data)
    if result:
        st.success("Пользователь зарегистрирован успешно!")
        return True
    return False

# UI для логина
def login_ui():
    st.sidebar.subheader("Вход")
    username = st.sidebar.text_input("Имя пользователя", key="login_username")
    password = st.sidebar.text_input("Пароль", type="password", key="login_password")
    if st.sidebar.button("Войти"):
        if authenticate(username, password):
            st.success("Вы успешно вошли!")
            st.rerun()

# UI для регистрации
def registration_ui():
    st.sidebar.subheader("Регистрация")
    username = st.sidebar.text_input("Имя пользователя для регистрации", key="reg_username")
    password = st.sidebar.text_input("Пароль для регистрации", type="password", key="reg_password")
    role = st.sidebar.selectbox("Роль для регистрации", ["user", "editor", "admin"], key="reg_role")
    if st.sidebar.button("Зарегистрироваться"):
        if register(username, password, role.upper()):
            st.success("Пользователь зарегистрирован успешно!")
            st.rerun()

# UI для презентаций
def presentations_ui():
    st.header("Презентации")
    
    headers = {
        "Authorization": f"Bearer {st.session_state['access_token']}"
    }
    presentations = make_request(f"{BACKEND_URL}/presentations", headers=headers)
    if presentations:
        st.subheader("Список презентаций")
        st.table(presentations)

    st.subheader("Добавить новую презентацию")
    google_slide_id = st.text_input("Google Slide ID", key="pres_add_google_id")
    name = st.text_input("Название", key="pres_add_name")

    if st.button("Добавить презентацию", key="pres_add_button"):
        data = {"google_slide_id": google_slide_id, "name": name}
        result = make_request(f"{BACKEND_URL}/presentations", method='POST', data=data, headers=headers)
        if result:
            st.success("Презентация добавлена успешно!")
            st.rerun()
    
    st.subheader("Обновить презентацию")
    pres_id_update = st.text_input("ID для обновления", key="pres_upd_id")
    google_slide_id_update = st.text_input("Google Slide ID", key="pres_upd_google_id")
    name_update = st.text_input("Название", key="pres_upd_name")
    
    if st.button("Обновить презентацию", key="pres_upd_button"):
        data = {"google_slide_id": google_slide_id_update, "name": name_update}
        result = make_request(f"{BACKEND_URL}/presentations/{pres_id_update}", method='PUT', data=data, headers=headers)
        if result:
            st.success("Презентация обновлена успешно!")
            st.rerun()

    st.subheader("Удалить презентацию")
    pres_id_delete = st.text_input("ID презентации для удаления", key="pres_del_id")
    if st.button("Удалить презентацию", key="pres_del_button"):
        result = make_request(f"{BACKEND_URL}/presentations/{pres_id_delete}", method='DELETE', headers=headers)
        if result:
            st.success("Презентация удалена успешно!")
            st.rerun()

# UI для слайдов
def slides_ui():
    st.header("Слайды")
    headers = {'Authorization': f'Bearer {st.session_state["access_token"]}'}
    slides = make_request(f"{BACKEND_URL}/slides", headers=headers)
    if slides:
        st.subheader("Список слайдов")
        st.table(slides)
    
    st.subheader("Добавить новый слайд")
    presentation_id = st.text_input("ID презентации", key="slide_add_pres_id")
    topic = st.text_input("Тема", key="slide_add_topic")
    industry = st.text_input("Индустрия", key="slide_add_industry")
    slide_type = st.selectbox("Тип слайда", ["CASE", "TITLE", "OTHER"], key="slide_add_type")
    added_by = st.text_input("Кем добавлено", key="slide_add_added_by")
    category_id = st.text_input("ID категории", key="slide_add_category_id")

    if st.button("Добавить слайд", key="slide_add_button"):
        data = {
            "presentation_id": int(presentation_id),
            "topic": topic,
            "industry": industry,
            "slide_type": slide_type,
            "added_by": int(added_by),
            "category_id": int(category_id)
        }
        result = make_request(f"{BACKEND_URL}/slides", method='POST', data=data, headers=headers)
        if result:
            st.success("Слайд добавлен успешно!")
            st.rerun()
    
    st.subheader("Обновить слайд")
    slide_id_update = st.text_input("ID слайда для обновления", key="slide_upd_id")
    presentation_id_update = st.text_input("ID презентации", key="slide_upd_pres_id")
    topic_update = st.text_input("Тема", key="slide_upd_topic")
    industry_update = st.text_input("Индустрия", key="slide_upd_industry")
    slide_type_update = st.selectbox("Тип слайда", ["CASE", "TITLE", "OTHER"], key="slide_upd_type")
    added_by_update = st.text_input("Кем добавлено", key="slide_upd_added_by")
    category_id_update = st.text_input("ID категории", key="slide_upd_category_id")
    if st.button("Обновить слайд", key="slide_upd_button"):
        data = {
            "presentation_id": int(presentation_id_update) if presentation_id_update else None,
            "topic": topic_update,
            "industry": industry_update,
            "slide_type": slide_type_update,
            "added_by": int(added_by_update) if added_by_update else None,
            "category_id": int(category_id_update) if category_id_update else None
        }
        data = {k: v for k, v in data.items() if v is not None}
        result = make_request(f"{BACKEND_URL}/slides/{slide_id_update}", method='PUT', data=data, headers=headers)
        if result:
            st.success("Слайд обновлён успешно!")
            st.rerun()
    
    st.subheader("Удалить слайд")
    slide_id_delete = st.text_input("ID слайда для удаления", key="slide_del_id")
    if st.button("Удалить слайд", key="slide_del_button"):
        result = make_request(f"{BACKEND_URL}/slides/{slide_id_delete}", method='DELETE', headers=headers)
        if result:
            st.success("Слайд удалён успешно!")
            st.rerun()

# UI для пользователей
def users_ui():
    st.header("Пользователи")
    if 'user_role' in st.session_state and st.session_state['user_role'] == 'ADMIN':
        st.subheader("Регистрация пользователя")
        username = st.text_input("Имя пользователя для регистрации", key="user_reg_username")
        password = st.text_input("Пароль для регистрации", type="password", key="user_reg_password")
        role = st.selectbox("Роль для регистрации", ["user", "editor", "admin"], key="user_reg_role")
        if st.button("Зарегистрировать нового пользователя", key="user_reg_button"):
            if register(username, password, role.upper()):
                st.success("Пользователь зарегистрирован успешно!")
                st.rerun()
    else:
        st.warning("У вас нет прав для доступа к управлению пользователями.")

def logs_ui():
    st.header("Логи")
    headers = {'Authorization': f'Bearer {st.session_state["access_token"]}'}
    logs = make_request(f"{BACKEND_URL}/logs", headers=headers)
    if logs and isinstance(logs, list):
        st.table(logs)
    else:
        st.info('Нет логов для отображения')

def errors_ui():
    st.header("Ошибки")
    headers = {'Authorization': f'Bearer {st.session_state["access_token"]}'}
    errors = make_request(f"{BACKEND_URL}/errors", headers=headers)
    if errors and isinstance(errors, list):
        st.table(errors)
    else:
        st.info('Нет ошибок для отображения')

# UI для результатов поиска
def search_results_ui():
    st.header("Результаты поиска")
    headers = {'Authorization': f'Bearer {st.session_state["access_token"]}'}
    
    st.subheader("Список результатов поиска")
    search_results = make_request(f"{BACKEND_URL}/search_results", headers=headers)
    if search_results and isinstance(search_results, list):
        st.table(search_results)

    st.subheader("Добавить новый результат поиска")
    user_id = st.text_input("ID пользователя", key="search_add_user_id")
    search_query = st.text_input("Запрос", key="search_add_query")
    result_slides = st.text_area("Результаты (JSON)", key="search_add_slides")
    search_date = st.text_input("Дата поиска (YYYY-MM-DD HH:MM:SS)", key="search_add_date")
    duration = st.text_input("Время поиска", key="search_add_duration")
    if st.button("Добавить результат поиска", key="search_add_button"):
        try:
            if search_slides := result_slides:
                # Преобразование JSON строки в список
                import json
                result_slides = json.loads(search_slides)
            data = {
                "user_id": int(user_id),
                "search_query": search_query,
                "result_slides": json.dumps(result_slides) if isinstance(result_slides, list) else result_slides,
                "search_date": search_date,
                "duration": duration
            }
            result = make_request(f"{BACKEND_URL}/search_results", method='POST', data=data, headers=headers)
            if result:
                st.success("Результат поиска добавлен успешно!")
                st.rerun()
        except json.JSONDecodeError:
            st.error("Неверный формат JSON для результатов слайдов.")

    st.subheader("Обновить результат поиска")
    result_id_update = st.text_input("ID результата для обновления", key="search_upd_id")
    user_id_update = st.text_input("ID пользователя", key="search_upd_user_id")
    search_query_update = st.text_input("Запрос", key="search_upd_query")
    result_slides_update = st.text_area("Результаты (JSON)", key="search_upd_slides")
    search_date_update = st.text_input("Дата поиска (YYYY-MM-DD HH:MM:SS)", key="search_upd_date")
    duration_update = st.text_input("Время поиска", key="search_upd_duration")
    if st.button("Обновить результат поиска", key="search_upd_button"):
        try:
            if search_slides_upd := result_slides_update:
                import json
                result_slides_update = json.loads(search_slides_update)
            data = {
                "user_id": int(user_id_update) if user_id_update else None,
                "search_query": search_query_update if search_query_update else None,
                "result_slides": json.dumps(result_slides_update) if isinstance(result_slides_update, list) else result_slides_update,
                "search_date": search_date_update if search_date_update else None,
                "duration": duration_update if duration_update else None
            }
            # Удаляем ключи с None значениями
            data = {k: v for k, v in data.items() if v is not None}
            result = make_request(f"{BACKEND_URL}/search_results/{result_id_update}", method='PUT', data=data, headers=headers)
            if result:
                st.success("Результат поиска обновлён успешно!")
                st.rerun()
        except json.JSONDecodeError:
            st.error("Неверный формат JSON для результатов слайдов.")
        except ValueError:
            st.error("ID пользователя и ID результата должны быть числами.")

    st.subheader("Удалить результат поиска")
    result_id_delete = st.text_input("ID результата для удаления", key="search_del_id")
    if st.button("Удалить результат поиска", key="search_del_button"):
        result = make_request(f"{BACKEND_URL}/search_results/{result_id_delete}", method='DELETE', headers=headers)
        if result:
            st.success("Результат поиска удалён успешно!")
            st.rerun()

# UI для управления базой данных
def db_management_ui():
    st.header('Управление БД (только для ADMIN)')
    if 'user_role' in st.session_state and st.session_state['user_role'] == 'ADMIN':

        st.subheader('Создать VIEW')
        if st.button("Создать VIEW", key="db_create_view_button"):
            headers = {'Authorization': f'Bearer {st.session_state["access_token"]}'}
            with st.spinner("Создаём VIEW..."):
                response = make_request(f"{BACKEND_URL}/create_view", method='POST', headers=headers)
            if response and response.get('msg') == "VIEW создано успешно":
                st.success("VIEW создано успешно!")
            elif response:
                st.error(response.get('msg', 'Неизвестная ошибка'))

        st.subheader('Создать TRIGGER')
        if st.button("Создать TRIGGER", key="db_create_trigger_button"):
            headers = {'Authorization': f'Bearer {st.session_state["access_token"]}'}
            with st.spinner("Создаём TRIGGER..."):
                response = make_request(f"{BACKEND_URL}/create_trigger", method='POST', headers=headers)
            if response and response.get('msg') == "TRIGGER создано успешно":
                st.success("TRIGGER создано успешно!")
            elif response:
                st.error(response.get('msg', 'Неизвестная ошибка'))

        st.subheader('Создать FUNCTION')
        if st.button("Создать FUNCTION", key="db_create_function_button"):
            headers = {'Authorization': f'Bearer {st.session_state["access_token"]}'}
            with st.spinner("Создаём FUNCTION..."):
                response = make_request(f"{BACKEND_URL}/create_function", method='POST', headers=headers)
            if response and response.get('msg') == "FUNCTION создано успешно":
                st.success("FUNCTION создано успешно!")
            elif response:
                st.error(response.get('msg', 'Неизвестная ошибка'))

        st.subheader('Создать STORED PROCEDURE')
        if st.button("Создать STORED PROCEDURE", key="db_create_procedure_button"):
            headers = {'Authorization': f'Bearer {st.session_state["access_token"]}'}
            with st.spinner("Создаём STORED PROCEDURE..."):
                response = make_request(f"{BACKEND_URL}/create_stored_procedure", method='POST', headers=headers)
            if response and response.get('msg') == "STORED PROCEDURE создано успешно":
                st.success("STORED PROCEDURE создано успешно!")
            elif response:
                st.error(response.get('msg', 'Неизвестная ошибка'))

        st.subheader('Резервное копирование базы данных')
        if st.button("Создать резервную копию", key="db_backup_button"):
            headers = {'Authorization': f'Bearer {st.session_state["access_token"]}'}
            with st.spinner("Создаём резервную копию..."):
                response = make_request(f"{BACKEND_URL}/create_backup", method='POST', headers=headers)
            st.write(f"Response type: {type(response)}")
            st.write(f"Response content: {response}")
            if response and isinstance(response, dict) and 'msg' in response:
                st.success(f"Резервная копия создана: {response['msg']}")
            else:
                st.error("Не удалось создать резервную копию.")


        # st.subheader('Восстановление базы данных')
        # backup_file = st.text_input("Путь к файлу резервной копии", key="db_restore_file")
        # if st.button("Восстановить базу данных", key="db_restore_button"):
        #     headers = {'Authorization': f'Bearer {st.session_state["access_token"]}'}
        #     data = {'backup_file': backup_file}
        #     with st.spinner("Восстанавливаем базу данных..."):
        #         response = make_request(f"{BACKEND_URL}/restore_backup", method='POST', data=data, headers=headers)
        #     if response:
        #         st.success(f"База данных восстановлена успешно: {response['msg']}")

        st.subheader("Просмотр VIEW")
        headers = {'Authorization': f'Bearer {st.session_state["access_token"]}'}
        views = make_request(f"{BACKEND_URL}/views", headers=headers)
        if views and isinstance(views, list):
            st.table(views)
        else:
            st.info("Нет доступных представлений (VIEW).")

        st.subheader("Просмотр данных из VIEW")
        view_name = st.text_input("Имя представления", key="view_data_name", value="slide_details_view")
        if st.button("Получить данные из VIEW", key="view_data_button"):
            headers = {'Authorization': f'Bearer {st.session_state["access_token"]}'}
            response = make_request(f"{BACKEND_URL}/view_data/{view_name}", method='GET', headers=headers)
            if response and isinstance(response, list):
                st.table(response)
            else:
                st.info("Нет данных для отображения.")

        st.subheader("Просмотр TRIGGER")
        triggers = make_request(f"{BACKEND_URL}/triggers", headers=headers)
        if triggers and isinstance(triggers, list):
            st.table(triggers)
        else:
            st.info("Нет триггеров для отображения.")

        st.subheader("Просмотр FUNCTION")
        functions = make_request(f"{BACKEND_URL}/functions", headers=headers)
        if functions and isinstance(functions, list):
            st.table(functions)
        else:
            st.info("Нет функций для отображения.")

        st.subheader("Просмотр STORED PROCEDURE")
        procedures = make_request(f"{BACKEND_URL}/stored_procedures", headers=headers)
        if procedures and isinstance(procedures, list):
            st.table(procedures)
        else:
            st.info("Нет хранимых процедур для отображения.")

    else:
        st.warning("У вас нет прав для доступа к управлению БД.")

# UI для экспорта данных
def export_data_ui():
    st.header("Экспорт данных")
    headers = {'Authorization': f'Bearer {st.session_state["access_token"]}'}
    if st.button("Экспорт презентаций в CSV", key="export_csv_button"):
        with st.spinner("Экспортируем презентации в CSV..."):
            response = make_request(f"{BACKEND_URL}/export_presentations_csv", headers=headers, expect_json=False)
        if response:
            # response.content уже содержит CSV
            st.download_button(
                label="Скачать CSV",
                data=response.decode('utf-8'),
                file_name=f"presentations_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv",
                mime="text/csv",
            )

    def slide_count_ui():
        st.header('Количество Слайдов по Категориям')
        
        if 'user_role' in st.session_state and st.session_state['user_role'] in ['ADMIN', 'EDITOR']:
            if st.button("Получить количество слайдов", key="get_slide_count_button"):
                headers = {'Authorization': f'Bearer {st.session_state["access_token"]}'}
                with st.spinner("Получаем данные..."):
                    response = make_request(f"{BACKEND_URL}/slide_count_by_category", method='GET', headers=headers)
                st.write(f"Response type: {type(response)}")
                st.write(f"Response content: {response}")
                if isinstance(response, list):
                    import pandas as pd
                    df = pd.DataFrame(response)
                    st.dataframe(df)
                    st.success("Данные успешно получены.")
                else:
                    st.error("Не удалось получить корректные данные.")
        else:
            st.warning("У вас нет прав для доступа к этой информации.")

    if st.button("Экспорт диаграммы распределения слайдов по категориям в JPEG", key="export_jpeg_button"):
        with st.spinner("Экспортируем диаграмму..."):
            response = make_request(f"{BACKEND_URL}/export_slide_distribution", headers=headers, expect_json=False)
        if response:
            st.download_button(
                label="Скачать JPEG",
                data=response,
                file_name=f"slide_distribution_{datetime.now().strftime('%Y%m%d%H%M%S')}.jpg",
                mime="image/jpeg",
            )

def main():
    st.title("Slide Manager")
    if 'access_token' not in st.session_state:
        login_ui()
        registration_ui()
    else:
        menu = ["Презентации", "Слайды", "Пользователи", "Логи", "Ошибки", "Поиск", "Управление БД", "Экспорт", "Проверка Токена"]
        choice = st.sidebar.selectbox("Разделы", menu)
        if choice == "Презентации":
            presentations_ui()
        elif choice == "Слайды":
            slides_ui()
        elif choice == "Пользователи":
            users_ui()
        elif choice == "Логи":
            logs_ui()
        elif choice == "Ошибки":
            errors_ui()
        elif choice == "Поиск":
            search_results_ui()
        elif choice == "Управление БД":
            db_management_ui()
        elif choice == "Экспорт":
            export_data_ui()
        elif choice == "Проверка Токена":
            check_token_ui()
        if st.sidebar.button("Выйти"):
            st.session_state.clear()
            st.rerun()

if __name__ == "__main__":
    main()
