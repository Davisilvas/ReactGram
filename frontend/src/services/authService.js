// req http de auth user

import { api, requestConfig } from '../utils/config';

//Register an user
const register = async (data) => {
    const config = requestConfig("POST", data)

    try {
        const res = await fetch(api + "/users/register", config)
            .then((res) => res.json())
            .catch((err) => err);

        if(res){
            localStorage.setItem("user", JSON.stringify(res))
        }

        return res
    } catch (error) {
        console.log(error)
    }
}

// logout an user
const logout = () => {
    localStorage.removeItem("user")
}

// log an user in
const login = async (data) => {
    const config = requestConfig("POST", data)

    try {
        const res = await fetch(api + "/users/login", config)
            .then((res) => res.json())
            .catch((err) => err)
        
        //console.log(res)

        if(res._id){
            localStorage.setItem("user", JSON.stringify(res))
        }

        return res
    } catch (error) {
        console.log(error)
    }
}

const authService = {
    register,
    logout,
    login
}

export default authService