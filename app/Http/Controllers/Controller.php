<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;

class Controller extends BaseController
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;

    public function getResponse($code, $message = false, $data = false){
        if (!$message) {
            switch ($code) {
                case 200:
                    # code...
                    $message = 'Success';
                    break;
                case 401:
                    # code...
                    $message = 'Unauthorized';
                    break;
                case 404:
                    # code...
                    $message = 'Not Found';
                    break;
                case 406:
                    # code...
                    $message = 'Not Accepted';
                    break;
                case 500:
                    # code...
                    $message = 'Error';
                    break;
                default:
                    # code...
                    $message = 'Undefined';
                    break;
            }
        }

        $response = [
            "responseCode"=> $code . '',
            "responseMessage"=> $message
        ];

        if ($data) {
            $response['data'] = $data;
        }

        return response($response);
    }
}
