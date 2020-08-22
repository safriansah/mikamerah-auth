<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Crypt;
use DB;
use Carbon\Carbon;
use App\Models\Users;
use App\Models\Profile;
use App\Models\Token;

class AuthController extends Controller
{
    //
    public function register (Request $request) {
        DB::beginTransaction();
        try {
            //code...
            $validator = Validator::make($request->all(), [
                'username' => 'required|max:255|unique:users',
                'password' => 'required|max:255',
                'fullname' => 'required|max:255',
                'email' => 'required|email|unique:profile',
                'phone' => 'required|numeric|unique:profile'
            ]);
    
            if ($validator->fails()) {
                return $this->getResponse(406, $validator->errors()->first());
            }
    
            $user = new Users;
            $user->username = $request->username;
            $user->password = Hash::make($request->password);
            $user->status = 1;
            $user->push();

            $profile = new Profile;
            $profile->id_user = $user->id;
            $profile->fullname = $request->fullname;
            $profile->email = $request->email;
            $profile->phone = $request->phone;
            $profile->push();

            DB::commit();
            return $this->getResponse(200);
        } catch (\Throwable $th) {
            DB::rollback();
            //throw $th;
            return $this->getResponse(500);
        }
    }

    public function login(Request $request){
        try {
            //code...
            $validator = Validator::make($request->all(), [
                'username' => 'required|max:255',
                'password' => 'required|max:255',
            ]);
            if ($validator->fails()) {
                return $this->getResponse(406, $validator->errors()->first());
            }

            $username = $request->username;
            $user = Users::where('username', $username)->orWhereHas('profile', function ($query) use ($username) {
                $query->where('email', $username)->orWhere('phone', $username);
            })->where('status', 1)->first();
            // dd($user);
            if (!$user) {
                # code...
                return $this->getResponse(401, 'Username doesnt match');
            } 
            
            if (!Hash::check($request->password, $user->password) ) {
                # code...
                return $this->getResponse(401, 'Password doesnt match');
            }
            
            $token = $this->generateToken($user);
            if (!$token) {
                # code...
                return $this->getResponse(500);
            }

            return $this->getResponse(200, false, [
                'token' => $token
            ]);
        } catch (\Throwable $th) {
            // throw $th;
            return $this->getResponse(500);
        }
    }

    public function checkToken(Request $request){
        try {
            //code...
            $validator = Validator::make($request->all(), [
                'token' => 'required',
            ]);
            if ($validator->fails()) {
                return $this->getResponse(406, $validator->errors()->first());
            }

            $token = Token::where('code', $request->token)->where('status', 1)->first();
            if (!$token) {
                return $this->getResponse(401, 'Token undefined');
            }
            
            $data = Crypt::decryptString($request->token);
            $data = json_decode($data);
            $diff = Carbon::createFromTimestamp($data->createdAt)->diffInHours(Carbon::now());
            if ($diff >= (int)env('TOKEN_DURATION_HOUR', '24')) {
                # code...
                return $this->getResponse(401, 'Token expired');
            } 
            
            return $this->getResponse(200, false, $data);
        } catch (\Throwable $th) {
            //throw $th;
            return $this->getResponse(500);
        }
    }

    public function logout(Request $request){
        try {
            //code...
            $validator = Validator::make($request->all(), [
                'token' => 'required',
            ]);
            if ($validator->fails()) {
                return $this->getResponse(406, $validator->errors()->first());
            }

            $token = Token::where('code', $request->token)->where('status', 1)->first();
            if (!$token) {
                return $this->getResponse(401, 'Token undefined');
            }

            $token->status = 0;
            $token->save();
            if (!$token) {
                return $this->getResponse(500);
            }

            return $this->getResponse(200);
        } catch (\Throwable $th) {
            //throw $th;
            return $this->getResponse(500);
        }
    }

    public function generateToken($user){
        try {
            //code...
            $time = Carbon::now();
            $data = [
                "id" => $user->id,
                "username" => $user->username,
                "fullname" => $user->profile->fullname,
                "email" => $user->profile->email,
                "phone" => $user->profile->phone,
                "createdAt" => $time->timestamp
            ];
            $code = Crypt::encryptString(json_encode($data));

            $token = new Token;
            $token->id_user = $user->id;
            $token->code = $code;
            $token->status = 1;
            $token->save();

            return $code;
        } catch (\Throwable $th) {
            //throw $th;
            return false;
        }
    }
}
