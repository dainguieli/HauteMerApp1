<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{

    //connexion
    public function login(Request $request)
    {
        try {
            $input = $request->all();
            $validator = Validator::make($input, [
                'email' => 'required|email',
                'password' => 'required',
            ]);
            if ($validator->fails()) {
                return response()->json(
                    [
                        'status' => false,
                        'message' => 'Erreur de validation',
                        'errors' => $validator->errors(),
                    ],
                    422
                );
            }
            if (!Auth::attempt($request->only(['email', 'password']))) {
                return response()->json(
                    [
                        'status' => false,
                        'message' => 'Email ou mot de passe incorrect',
                        'errors' => $validator->errors(),
                    ],
                    401
                );
            }
            $user = User::where('email', $request->email)->first();
            return response()->json(
                [
                    'status' => true,
                    'message' => 'Utilisateur connecté avec succés',
                    'data' => [
                        "token" => $user->createToken('auth_user')->plainTextToken,
                        "token_type" => "Bearer",
                    ],
                ],
            );
        } catch (\Throwable $th) {

            return response()->json(
                [
                    'status' => false,
                    'message' => $th->getMessage(),
                ],
                500
            );
        }
    }
//modifier
public function edite(Request $request)
{
    try {
        $input = $request->all();
        $validator = Validator::make($input, [
            'email' => 'email|unique:users,email',
          
        ]);
        if ($validator->fails()) {
            return response()->json(
                [
                    'status' => false,
                    'message' => 'Erreur de validation',
                    'errors' => $validator->errors(),
                ],
                422
            );
        }
       $request->user()->update($input);

        return response()->json(
            [
                'status' => true,
                'message' => 'Utilisateur modifié avec succés',
                'data' => $request->user(),
            ],
        );
    } catch (\Throwable $th) {

        return response()->json(
            [
                'status' => false,
                'message' => $th->getMessage(),
            ],
            500
        );
    }
}

public function updatePassword(Request $request)
{
    try {
        $input = $request->all();
        $validator = Validator::make($input, [
            'old_password' => 'required',
            'new_password'=>'require|confirmed'
        ]);
        if ($validator->fails()) {
            return response()->json(
                [
                    'status' => false,
                    'message' => 'Erreur de validation',
                    'errors' => $validator->errors(),
                ],
                422
            );
        }
      if (!Hash::check($input['old_password'],$request->user()->password)) {
        return response()->json(
            [
                'status' => false,
                'message' => "l'ancien mot de passe est incorrect",

            ],
            401
        );
      }
      $input['password']=Hash::make($input['new_password']);
      $request->user()->update($input);
        return response()->json(
            [
                'status' => true,
                'message' => "Mot de passe modifié avec succés",
                'data' => $request->user(),
            ],
        );
    } catch (\Throwable $th) {

        return response()->json(
            [
                'status' => false,
                'message' => $th->getMessage(),
            ],
            500
        );
    }
}

    public function register(Request $request)
    {
        try {
            $input = $request->all();
            $validator = Validator::make($input, [
                'name' => 'required',
                'email' => 'required|email|unique:users,email',
                'password' => 'required|confirmed',
                'password_confirmation' => 'required',
            ]);
            if ($validator->fails()) {
                return response()->json(
                    [
                        'status' => false,
                        'message' => 'Erreur de validation',
                        'errors' => $validator->errors(),
                    ],
                    422
                );
            }
            $input['password'] = Hash::make($request->password);
            $user = User::create($input);
            return response()->json(
                [
                    'status' => true,
                    'message' => 'Utilisateur creé avec succés',
                    'data' => [
                        "token" => $user->createToken('auth_user')->plainTextToken,
                        "token_type" => "Bearer",
                    ],
                ],
            );
        } catch (\Throwable $th) {

            return response()->json(
                [
                    'status' => false,
                    'message' => $th->getMessage(),
                ],
                500
            );
        }
    }

    public function profile(Request $request){
        return response()->json(
            [
                'status' => true,
                'message' => 'Profile utilisateur',
                'data' => $request->user(),   
            ],
        );
    }
}
