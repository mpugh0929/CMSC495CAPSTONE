import sqlite3

def find_student(emplid, email):
    # connect to the db
    conn = sqlite3.connect('students.db')
    cursor = conn.cursor()

    # execute the parameterized query - automatically escapes special characters
    cursor.execute("SELECT * FROM Students WHERE EMPLID=? AND EMAIL=?", (emplid, email))

    # get results
    rows = cursor.fetchall()

    # close the connection to prevent memory leakage
    conn.close()

    return rows

def main():
    emplid = input("Enter EMPLID: ")
    email = input("Enter email: ")

    student_data = find_student(emplid, email)

    if student_data:
        print("Student found:")
        for row in student_data:
            print(row)
    else:
        print("No student found.")

main()
